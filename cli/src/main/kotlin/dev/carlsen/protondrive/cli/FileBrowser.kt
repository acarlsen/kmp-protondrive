package dev.carlsen.protondrive.cli

import dev.carlsen.protondrive.sdk.nodes.DriveClient
import dev.carlsen.protondrive.sdk.nodes.Node
import kotlinx.coroutines.withContext
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.format.char
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import org.jline.terminal.Terminal
import org.jline.terminal.TerminalBuilder
import org.jline.utils.NonBlockingReader
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Interactive Drive file browser: arrow keys + Enter to navigate (including a
 * ".." row to go up, so navigation is uniformly select-and-Enter), plus
 * single-key shortcuts (r/n/e/d/q). Falls back to a numbered, line-based
 * prompt when stdin/stdout isn't a real terminal (e.g. some IDE run
 * configurations, or piped output) since raw-mode key reading needs a genuine
 * TTY - see README.md's "Testing the CLI" section for how to get a real one.
 */
class FileBrowser(private val driveClient: DriveClient, private val onLogout: suspend () -> Unit) {

    private val displayTimeZone = TimeZone.currentSystemDefault()
    private val dateFormatter = LocalDateTime.Format {
        year()
        char('-')
        monthNumber()
        char('-')
        day()
        char(' ')
        hour()
        char(':')
        minute()
    }

    /** An item marked with 'x' (cut) or 'c' (copy), waiting to be pasted with 'v' into whichever folder is being viewed when that's pressed. */
    private data class Clipboard(val node: Node, val parent: Node, val isCut: Boolean)

    suspend fun run(root: Node) {
        val terminal = runCatching { TerminalBuilder.builder().system(true).build() }.getOrNull()
        if (terminal == null || terminal.type == Terminal.TYPE_DUMB || terminal.type == Terminal.TYPE_DUMB_COLOR) {
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                terminal?.close()
            }
            runFallback(root)
            return
        }
        try {
            runInteractive(terminal, root)
        } finally {
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                terminal.close()
            }
        }
    }

    // ---- Interactive (raw-mode, arrow-key) browser ----

    /** A displayed row: `null` represents the ".." (up to parent) entry, shown whenever [ArrayDeque] isn't empty. */
    private suspend fun rowsFor(current: Node, hasParent: Boolean): List<Node?> {
        val children = driveClient.listChildren(current).sortedForDisplay()
        return if (!hasParent) children else listOf<Node?>(null) + children
    }

    private suspend fun runInteractive(terminal: Terminal, root: Node) {
        val stack = ArrayDeque<Pair<Node, List<Node?>>>()
        var current = root
        var rows = rowsFor(current, stack.isNotEmpty())
        var selected = 0
        var status: String? = null
        var clipboard: Clipboard? = null

        fun goUp() {
            val parentState = stack.removeLastOrNull()
            if (parentState != null) {
                current = parentState.first
                rows = parentState.second
                selected = 0
            }
        }

        suspend fun refresh(selectName: String? = null) {
            rows = rowsFor(current, stack.isNotEmpty())
            selected = selectName?.let { name -> rows.indexOfFirst { it?.name == name } }?.takeIf { it >= 0 }
                ?: selected.coerceIn(0, (rows.size - 1).coerceAtLeast(0))
        }

        suspend fun downloadSelected(target: Node): String {
            val destinationInput = promptLine(terminal, "Save \"${target.name}\" to (Esc to cancel): ", initial = target.name)
            if (destinationInput.isNullOrBlank()) return "Download cancelled."
            val destination = destinationInput.trim()

            if (SystemFileSystem.exists(Path(destination))) {
                val confirmed = promptLine(terminal, "\"$destination\" already exists, overwrite? (y/N): ")
                if (confirmed?.trim()?.lowercase() != "y") return "Download cancelled."
            }

            val writer = terminal.writer()
            writer.println()
            val result = performDownload(target, current, destination) { line ->
                writer.print("\r" + line.padEnd(70))
                writer.flush()
            }
            writer.println()
            return result
        }

        suspend fun uploadHere(): String {
            val localPath = promptLine(terminal, "Local file to upload (full path, Esc to cancel): ")
            if (localPath.isNullOrBlank()) return "Upload cancelled."
            val trimmedPath = localPath.trim()
            val uploadName = Path(trimmedPath).name
            val existing = rows.filterNotNull().firstOrNull { it.name == uploadName }

            if (existing != null && existing.isFolder) {
                return "A folder named \"$uploadName\" already exists here."
            }
            if (existing != null) {
                val confirmed = promptLine(terminal, "\"$uploadName\" already exists here - upload as a new revision? (y/N): ")
                if (confirmed?.trim()?.lowercase() != "y") return "Upload cancelled."
            }

            val writer = terminal.writer()
            writer.println()
            val result = performUpload(trimmedPath, current, existingNode = existing) { line ->
                writer.print("\r" + line.padEnd(70))
                writer.flush()
            }
            writer.println()
            refresh(selectName = uploadName)
            return result
        }

        suspend fun pasteHere(): String {
            val entry = clipboard ?: return "Nothing to paste - cut ('x') or copy ('c') something first."
            return if (entry.isCut) {
                val moveResult = runCatching { driveClient.moveNode(entry.node, entry.parent, current) }
                val result = moveResult.fold(onSuccess = { "Moved \"${entry.node.name}\" here." }, onFailure = { "Failed to move: ${it.message}" })
                // Only clear on success - a failed move (e.g. a name conflict, or the item's
                // parent having changed since it was cut) should let the user retry without
                // re-cutting, not silently discard their selection.
                if (moveResult.isSuccess) clipboard = null
                refresh(selectName = entry.node.name)
                result
            } else {
                val result = runCatching { driveClient.copyNode(entry.node, entry.parent, current) }
                    .fold(onSuccess = { "Copied \"${entry.node.name}\" here." }, onFailure = { "Failed to copy: ${it.message}" })
                refresh(selectName = entry.node.name)
                result
            }
        }

        val previousAttributes = terminal.enterRawMode()
        try {
            while (true) {
                render(terminal, stack, current, rows, selected, status, clipboard?.let { it.node.name to it.isCut })
                status = null

                when (readKey(terminal.reader())) {
                    Key.Up -> if (rows.isNotEmpty()) selected = (selected - 1 + rows.size) % rows.size
                    Key.Down -> if (rows.isNotEmpty()) selected = (selected + 1) % rows.size
                    Key.Enter -> {
                        val target = rows.getOrNull(selected)
                        if (target == null && rows.isNotEmpty() && selected == 0 && stack.isNotEmpty()) {
                            goUp()
                        } else if (target != null && target.isFolder) {
                            stack.addLast(current to rows)
                            current = target
                            rows = rowsFor(current, stack.isNotEmpty())
                            selected = 0
                        }
                    }
                    Key.Left, Key.Backspace -> goUp()
                    Key.Refresh -> {
                        refresh()
                        status = "Refreshed."
                    }
                    Key.NewFolder -> {
                        val name = promptLine(terminal, "New folder name (Esc to cancel): ")
                        if (!name.isNullOrBlank()) {
                            val trimmed = name.trim()
                            status = runCatching { driveClient.createFolder(current, trimmed) }
                                .fold(onSuccess = { "Created \"$trimmed\"." }, onFailure = { "Failed to create folder: ${it.message}" })
                            refresh(selectName = trimmed)
                        }
                    }
                    Key.Rename -> {
                        val target = rows.getOrNull(selected)
                        if (target != null) {
                            val name = promptLine(terminal, "Rename \"${target.name}\" to (Esc to cancel): ", initial = target.name)
                            if (!name.isNullOrBlank() && name.trim() != target.name) {
                                val trimmed = name.trim()
                                status = runCatching { driveClient.renameNode(target, current, trimmed) }
                                    .fold(onSuccess = { "Renamed to \"$trimmed\"." }, onFailure = { "Failed to rename: ${it.message}" })
                                refresh(selectName = trimmed)
                            }
                        }
                    }
                    Key.Delete -> {
                        val target = rows.getOrNull(selected)
                        if (target != null) {
                            val confirmed = promptLine(terminal, "Move \"${target.name}\" to trash? (y/N): ")
                            if (confirmed?.trim()?.lowercase() == "y") {
                                status = runCatching { driveClient.trashNode(target) }
                                    .fold(onSuccess = { "Moved \"${target.name}\" to trash." }, onFailure = { "Failed to delete: ${it.message}" })
                                refresh()
                            }
                        }
                    }
                    Key.Download -> {
                        val target = rows.getOrNull(selected)
                        status = if (target == null || target.isFolder) "Select a file to download." else downloadSelected(target)
                    }
                    Key.Upload -> status = uploadHere()
                    Key.Cut -> {
                        val target = rows.getOrNull(selected)
                        status = if (target == null) {
                            "Select an item to cut."
                        } else {
                            clipboard = Clipboard(target, current, isCut = true)
                            "Marked \"${target.name}\" to move - navigate to a folder and press v to paste."
                        }
                    }
                    Key.Copy -> {
                        val target = rows.getOrNull(selected)
                        status = when {
                            target == null -> "Select an item to copy."
                            target.isFolder -> "Only files can be copied, not folders."
                            else -> {
                                clipboard = Clipboard(target, current, isCut = false)
                                "Marked \"${target.name}\" to copy - navigate to a folder and press v to paste."
                            }
                        }
                    }
                    Key.Paste -> status = pasteHere()
                    Key.Logout -> {
                        val confirmed = promptLine(terminal, "Log out and clear saved session? (y/N): ")
                        if (confirmed?.trim()?.lowercase() == "y") {
                            onLogout()
                            return
                        }
                    }
                    Key.Quit, Key.Escape, Key.Eof -> return
                    Key.Right, Key.Other -> {}
                }
            }
        } finally {
            terminal.attributes = previousAttributes
        }
    }

    private fun render(
        terminal: Terminal,
        stack: ArrayDeque<Pair<Node, List<Node?>>>,
        current: Node,
        rows: List<Node?>,
        selected: Int,
        status: String?,
        clipboard: Pair<String, Boolean>? = null,
    ) {
        val writer = terminal.writer()
        writer.print("[H[2J")

        val breadcrumb = (stack.map { it.first.name } + current.name).joinToString(" / ")
        writer.println("Proton Drive — $breadcrumb")
        writer.println(
            "↑/↓ move   Enter open/up   r refresh   n new folder   e rename   d delete   g download   " +
                "u upload   x cut   c copy   v paste   l logout   q quit",
        )
        clipboard?.let { (name, isCut) -> writer.println("Clipboard: ${if (isCut) "move" else "copy"} \"$name\"") }
        status?.let { writer.println(it) }
        writer.println()

        if (rows.isEmpty()) {
            writer.println("  (empty)")
        } else {
            val nameWidth = rows.maxOf { (it?.name?.length ?: 2) + if (it?.isFolder != false) 1 else 0 }.coerceIn(20, 50)
            writer.println("    " + "Name".padEnd(nameWidth) + "  " + "Modified".padEnd(16) + "  Size")
            rows.forEachIndexed { index, node ->
                val nameField = displayName(node).let {
                    if (it.length > nameWidth) it.take(nameWidth - 1) + "…" else it.padEnd(nameWidth)
                }
                val modified = (node?.let { formatModifiedTime(it.modifiedTime) } ?: "-").padEnd(16)
                val size = if (node == null || node.isFolder) "-" else node.size?.let(::formatSize) ?: "?"
                val line = "$nameField  $modified  $size"
                if (index == selected) {
                    writer.println("  [7m> $line[0m")
                } else {
                    writer.println("    $line")
                }
            }
        }
        writer.flush()
    }

    private fun displayName(node: Node?): String = if (node == null) ".." else node.name + if (node.isFolder) "/" else ""

    /**
     * Runs the actual download once a destination/overwrite decision has been made -
     * shared by the interactive and fallback browsers, which differ only in how they
     * render the progress line and the final result.
     */
    private suspend fun performDownload(target: Node, parent: Node, destination: String, onProgressLine: (String) -> Unit): String {
        val sink = SystemFileSystem.sink(Path(destination)).buffered()
        return try {
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                driveClient.downloadFile(target, parent, sink) { downloaded ->
                    val total = target.size
                    val progress = if (total != null && total > 0) {
                        "${formatSize(downloaded)} / ${formatSize(total)} (${downloaded * 100 / total}%)"
                    } else {
                        formatSize(downloaded)
                    }
                    onProgressLine("Downloading \"${target.name}\": $progress")
                }
            }
            "Downloaded \"${target.name}\" to \"$destination\"."
        } catch (e: Exception) {
            "Failed to download \"${target.name}\": ${e.message}"
        } finally {
            withContext(kotlinx.coroutines.Dispatchers.IO) { sink.close() }
        }
    }

    /**
     * Uploads a local file into [parent] - shared by the interactive and fallback browsers,
     * which differ only in how they render the progress line and the final result. If
     * [existingNode] is given (a same-named item already present in [parent]), uploads a new
     * *revision* of it instead of creating a new file.
     */
    private suspend fun performUpload(localPath: String, parent: Node, existingNode: Node? = null, onProgressLine: (String) -> Unit): String {
        val path = Path(localPath)
        val metadata = SystemFileSystem.metadataOrNull(path)
        if (metadata == null) return "\"$localPath\" does not exist."
        if (!metadata.isRegularFile) return "\"$localPath\" is not a file."

        val name = path.name
        val totalSize = metadata.size
        val mediaType = ThumbnailGenerator.mimeTypeFor(name)
        val localFile = java.io.File(localPath)
        // kotlinx.io's FileMetadata doesn't expose a modification time, so this uses
        // java.io.File directly (fine - the CLI is desktop-JVM only anyway, same as
        // ThumbnailGenerator). Falls back to "now" if the OS reports 0 (e.g. missing file,
        // though metadataOrNull above already ruled that out; kept defensive regardless).
        val modificationTime = localFile.lastModified().takeIf { it > 0 }
            ?.let { Instant.fromEpochMilliseconds(it) }
            ?: Clock.System.now()
        val thumbnail = if (ThumbnailGenerator.isSupportedForThumbnail(name)) {
            ThumbnailGenerator.generatePreview(localFile, name)
        } else {
            null
        }
        val source = SystemFileSystem.source(path).buffered()
        return try {
            var uploaded = 0L
            val onProgress: (Long) -> Unit = { delta ->
                uploaded += delta
                val progress = if (totalSize > 0) {
                    "${formatSize(uploaded)} / ${formatSize(totalSize)} (${uploaded * 100 / totalSize}%)"
                } else {
                    formatSize(uploaded)
                }
                onProgressLine("Uploading \"$name\": $progress")
            }
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                if (existingNode != null) {
                    driveClient.uploadRevision(
                        node = existingNode,
                        parent = parent,
                        source = source,
                        modificationTime = modificationTime,
                        thumbnails = listOfNotNull(thumbnail),
                        onProgress = onProgress,
                    )
                } else {
                    driveClient.uploadFile(
                        parent = parent,
                        name = name,
                        source = source,
                        mediaType = mediaType,
                        modificationTime = modificationTime,
                        thumbnails = listOfNotNull(thumbnail),
                        onProgress = onProgress,
                    )
                }
            }
            if (existingNode != null) "Uploaded \"$name\" as a new revision." else "Uploaded \"$name\"."
        } catch (e: Exception) {
            "Failed to upload \"$name\": ${e.message}"
        } finally {
            withContext(kotlinx.coroutines.Dispatchers.IO) { source.close() }
        }
    }

    private fun promptLine(terminal: Terminal, label: String, initial: String = ""): String? {
        val writer = terminal.writer()
        writer.print("\r\n$label")
        writer.print(initial)
        terminal.flush()

        val reader = terminal.reader()
        val input = StringBuilder(initial)
        while (true) {
            when (val c = reader.read()) {
                13, 10 -> return input.toString()
                27 -> return null
                127, 8 -> if (input.isNotEmpty()) {
                    input.deleteCharAt(input.length - 1)
                    writer.print("\b \b")
                    terminal.flush()
                }
                NonBlockingReader.EOF -> return null
                else -> if (c in 32..126) {
                    input.append(c.toChar())
                    writer.print(c.toChar())
                    terminal.flush()
                }
            }
        }
    }

    private enum class Key {
        Up, Down, Left, Right, Enter, Backspace, Escape, Quit, Refresh, NewFolder, Rename, Delete,
        Download, Upload, Cut, Copy, Paste, Logout, Eof, Other,
    }

    private fun readKey(reader: NonBlockingReader): Key {
        val c = reader.read()
        if (c == NonBlockingReader.EOF) return Key.Eof
        if (c == 27) {
            // Arrow keys arrive as ESC '[' <letter> in a fast burst; a lone ESC keypress
            // will time out waiting for the rest of the sequence.
            val next1 = reader.read(80)
            if (next1 != '['.code) return Key.Escape
            return when (reader.read(80)) {
                'A'.code -> Key.Up
                'B'.code -> Key.Down
                'C'.code -> Key.Right
                'D'.code -> Key.Left
                else -> Key.Other
            }
        }
        return when (c) {
            13, 10 -> Key.Enter
            127, 8 -> Key.Backspace
            'q'.code, 'Q'.code -> Key.Quit
            'r'.code, 'R'.code -> Key.Refresh
            'n'.code, 'N'.code -> Key.NewFolder
            'e'.code, 'E'.code -> Key.Rename
            'd'.code, 'D'.code -> Key.Delete
            'g'.code, 'G'.code -> Key.Download
            'u'.code, 'U'.code -> Key.Upload
            'x'.code, 'X'.code -> Key.Cut
            'c'.code, 'C'.code -> Key.Copy
            'v'.code, 'V'.code -> Key.Paste
            'l'.code, 'L'.code -> Key.Logout
            else -> Key.Other
        }
    }

    // ---- Fallback (numbered, line-based) browser for non-TTY environments ----

    private suspend fun runFallback(root: Node) {
        println()
        println("No interactive terminal detected - falling back to a numbered prompt.")
        println("(Run the installed binary directly, not via `gradlew :cli:run`, for arrow-key navigation - see README.md.)")

        val stack = ArrayDeque<Pair<Node, List<Node>>>()
        var current = root
        var items = driveClient.listChildren(current).sortedForDisplay()
        var clipboard: Clipboard? = null

        while (true) {
            println()
            println("Proton Drive — " + (stack.map { it.first.name } + current.name).joinToString(" / "))
            clipboard?.let { println("Clipboard: ${if (it.isCut) "move" else "copy"} \"${it.node.name}\"") }
            if (items.isEmpty()) {
                println("  (empty)")
            } else {
                items.forEachIndexed { index, node ->
                    val kind = if (node.isFolder) "[folder]" else "[file]  "
                    val size = if (!node.isFolder) node.size?.let { "  " + formatSize(it) }.orEmpty() else ""
                    println("  ${index + 1}. $kind ${node.name}  ${formatModifiedTime(node.modifiedTime)}$size")
                }
            }
            print(
                "Number to open, 'r' refresh, 'n' new folder, 'e N' rename, 'd N' delete, 'g N' download, 'u' upload, " +
                    "'x N' cut, 'c N' copy, 'v' paste, '..' up, 'l' logout, 'q' quit: ",
            )
            val input = readlnOrNull()?.trim().orEmpty()
            val parts = input.split(Regex("\\s+"), limit = 2)
            when (parts.first()) {
                "q", "Q" -> return
                "l", "L" -> {
                    print("Log out and clear saved session? (y/N): ")
                    if (readlnOrNull()?.trim()?.lowercase() == "y") {
                        onLogout()
                        return
                    }
                }
                ".." -> {
                    val parentState = stack.removeLastOrNull()
                    if (parentState != null) {
                        current = parentState.first
                        items = parentState.second
                    }
                }
                "r", "R" -> items = driveClient.listChildren(current).sortedForDisplay()
                "n", "N" -> {
                    print("New folder name: ")
                    val name = readlnOrNull()?.trim()
                    if (!name.isNullOrBlank()) {
                        runCatching { driveClient.createFolder(current, name) }
                            .onFailure { println("Failed to create folder: ${it.message}") }
                        items = driveClient.listChildren(current).sortedForDisplay()
                    }
                }
                "e", "E" -> {
                    val target = parts.getOrNull(1)?.toIntOrNull()?.let { items.getOrNull(it - 1) }
                    if (target == null) {
                        println("Usage: e <number>")
                    } else {
                        print("Rename \"${target.name}\" to: ")
                        val name = readlnOrNull()?.trim()
                        if (!name.isNullOrBlank() && name != target.name) {
                            runCatching { driveClient.renameNode(target, current, name) }
                                .onFailure { println("Failed to rename: ${it.message}") }
                            items = driveClient.listChildren(current).sortedForDisplay()
                        }
                    }
                }
                "d", "D" -> {
                    val target = parts.getOrNull(1)?.toIntOrNull()?.let { items.getOrNull(it - 1) }
                    if (target == null) {
                        println("Usage: d <number>")
                    } else {
                        print("Move \"${target.name}\" to trash? (y/N): ")
                        if (readlnOrNull()?.trim()?.lowercase() == "y") {
                            runCatching { driveClient.trashNode(target) }
                                .onFailure { println("Failed to delete: ${it.message}") }
                            items = driveClient.listChildren(current).sortedForDisplay()
                        }
                    }
                }
                "g", "G" -> {
                    val target = parts.getOrNull(1)?.toIntOrNull()?.let { items.getOrNull(it - 1) }
                    if (target == null || target.isFolder) {
                        println("Usage: g <number> (must be a file)")
                    } else {
                        print("Save \"${target.name}\" to [${target.name}]: ")
                        val destInput = readlnOrNull()?.trim()
                        val destination = destInput?.ifBlank { null } ?: target.name
                        val proceed = if (SystemFileSystem.exists(Path(destination))) {
                            print("\"$destination\" already exists, overwrite? (y/N): ")
                            readlnOrNull()?.trim()?.lowercase() == "y"
                        } else {
                            true
                        }
                        if (proceed) {
                            val result = performDownload(target, current, destination) { line -> print("\r" + line.padEnd(70)) }
                            println()
                            println(result)
                        }
                    }
                }
                "u", "U" -> {
                    print("Local file to upload (full path): ")
                    val localPath = readlnOrNull()?.trim()
                    if (!localPath.isNullOrBlank()) {
                        val uploadName = Path(localPath).name
                        val existing = items.firstOrNull { it.name == uploadName }
                        val proceed = when {
                            existing != null && existing.isFolder -> {
                                println("A folder named \"$uploadName\" already exists here.")
                                false
                            }
                            existing != null -> {
                                print("\"$uploadName\" already exists here - upload as a new revision? (y/N): ")
                                readlnOrNull()?.trim()?.lowercase() == "y"
                            }
                            else -> true
                        }
                        if (proceed) {
                            val result = performUpload(localPath, current, existingNode = existing) { line -> print("\r" + line.padEnd(70)) }
                            println()
                            println(result)
                            items = driveClient.listChildren(current).sortedForDisplay()
                        }
                    }
                }
                "x", "X" -> {
                    val target = parts.getOrNull(1)?.toIntOrNull()?.let { items.getOrNull(it - 1) }
                    if (target == null) {
                        println("Usage: x <number>")
                    } else {
                        clipboard = Clipboard(target, current, isCut = true)
                        println("Marked \"${target.name}\" to move - navigate to a folder and use 'v' to paste.")
                    }
                }
                "c", "C" -> {
                    val target = parts.getOrNull(1)?.toIntOrNull()?.let { items.getOrNull(it - 1) }
                    when {
                        target == null -> println("Usage: c <number>")
                        target.isFolder -> println("Only files can be copied, not folders.")
                        else -> {
                            clipboard = Clipboard(target, current, isCut = false)
                            println("Marked \"${target.name}\" to copy - navigate to a folder and use 'v' to paste.")
                        }
                    }
                }
                "v", "V" -> {
                    val entry = clipboard
                    if (entry == null) {
                        println("Nothing to paste - cut ('x') or copy ('c') something first.")
                    } else if (entry.isCut) {
                        val moveResult = runCatching { driveClient.moveNode(entry.node, entry.parent, current) }
                        moveResult.fold(
                            onSuccess = { println("Moved \"${entry.node.name}\" here.") },
                            onFailure = { println("Failed to move: ${it.message}") },
                        )
                        // Only clear on success - see the interactive browser's pasteHere() for why.
                        if (moveResult.isSuccess) clipboard = null
                        items = driveClient.listChildren(current).sortedForDisplay()
                    } else {
                        runCatching { driveClient.copyNode(entry.node, entry.parent, current) }
                            .fold(
                                onSuccess = { println("Copied \"${entry.node.name}\" here.") },
                                onFailure = { println("Failed to copy: ${it.message}") },
                            )
                        items = driveClient.listChildren(current).sortedForDisplay()
                    }
                }
                else -> {
                    val target = parts.first().toIntOrNull()?.let { items.getOrNull(it - 1) }
                    if (target != null && target.isFolder) {
                        stack.addLast(current to items)
                        current = target
                        items = driveClient.listChildren(current).sortedForDisplay()
                    } else if (target == null) {
                        println("Not a valid choice.")
                    }
                }
            }
        }
    }

    private fun formatModifiedTime(epochSeconds: Long): String =
        if (epochSeconds <= 0) {
            "-"
        } else {
            dateFormatter.format(Instant.fromEpochSeconds(epochSeconds).toLocalDateTime(displayTimeZone))
        }

    private fun formatSize(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = listOf("KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var unitIndex = -1
        while (value >= 1024 && unitIndex < units.size - 1) {
            value /= 1024
            unitIndex++
        }
        return "%.1f %s".format(value, units[unitIndex])
    }

    private fun List<Node>.sortedForDisplay(): List<Node> =
        sortedWith(compareBy({ !it.isFolder }, { it.name.lowercase() }))
}
