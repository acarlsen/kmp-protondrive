package dev.carlsen.protondrive.cli

import dev.carlsen.protondrive.cli.ThumbnailGenerator.generatePreview
import dev.carlsen.protondrive.sdk.nodes.UploadThumbnail
import org.apache.pdfbox.Loader
import org.apache.pdfbox.rendering.PDFRenderer
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageWriteParam

private const val PREVIEW_MAX_DIMENSION = 512
private const val PREVIEW_THUMBNAIL_TYPE = 1
private const val PDF_RENDER_DPI = 100f

// Proton's hard limit is 69632 bytes *encrypted*; leave headroom for OpenPGP packet/IV/MDC
// overhead (a few dozen bytes) rather than computing it exactly.
private const val PREVIEW_TARGET_MAX_SIZE_BYTES = 69_632 - 2_000

private val RASTER_IMAGE_EXTENSIONS = setOf("jpg", "jpeg", "png")
private val SUPPORTED_THUMBNAIL_EXTENSIONS = RASTER_IMAGE_EXTENSIONS + "pdf"

/**
 * Generates Proton Drive's "Preview" thumbnail (type 1: 512px max dimension, max 69632 bytes
 * encrypted) for jpg/png/pdf files - best-effort, desktop-JVM only (`java.awt`/`ImageIO`, plus
 * PDFBox for rasterizing a PDF's first page). This is exactly the kind of platform-specific
 * image processing [UploadThumbnail]'s kdoc says the SDK deliberately leaves to the host app,
 * matching how even Proton's own JS SDK doesn't generate thumbnails itself.
 */
object ThumbnailGenerator {
    fun isSupportedForThumbnail(fileName: String): Boolean =
        fileName.substringAfterLast('.', "").lowercase() in SUPPORTED_THUMBNAIL_EXTENSIONS

    fun mimeTypeFor(fileName: String): String = when (fileName.substringAfterLast('.', "").lowercase()) {
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "gif" -> "image/gif"
        "pdf" -> "application/pdf"
        "txt" -> "text/plain"
        else -> "application/octet-stream"
    }

    /** Returns `null` (rather than throwing) if [file] can't be rasterized or encoding fails to fit the size budget - a missing preview isn't worth failing the whole upload over. */
    fun generatePreview(file: File, fileName: String): UploadThumbnail? = runCatching {
        val extension = fileName.substringAfterLast('.', "").lowercase()
        val original = when (extension) {
            in RASTER_IMAGE_EXTENSIONS -> ImageIO.read(file)
            "pdf" -> renderFirstPdfPage(file)
            else -> null
        } ?: return null

        val scale = (PREVIEW_MAX_DIMENSION.toDouble() / maxOf(original.width, original.height)).coerceAtMost(1.0)
        val targetWidth = (original.width * scale).toInt().coerceAtLeast(1)
        val targetHeight = (original.height * scale).toInt().coerceAtLeast(1)

        val scaled = BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_RGB)
        val graphics = scaled.createGraphics()
        graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
        graphics.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
        graphics.drawImage(original, 0, 0, targetWidth, targetHeight, null)
        graphics.dispose()

        val bytes = encodeJpegUnderSizeBudget(scaled) ?: return null
        UploadThumbnail(type = PREVIEW_THUMBNAIL_TYPE, data = bytes)
    }.getOrNull()

    /** Rasterizes just the first page - a modest DPI is fine since [generatePreview] downscales to 512px right after anyway. Returns `null` for a zero-page (or otherwise unrenderable) PDF. */
    private fun renderFirstPdfPage(file: File): BufferedImage? =
        Loader.loadPDF(file).use { document ->
            if (document.numberOfPages == 0) return null
            PDFRenderer(document).renderImageWithDPI(0, PDF_RENDER_DPI)
        }

    /** Encodes at decreasing JPEG quality until under Proton's size budget, giving up after a few attempts. */
    private fun encodeJpegUnderSizeBudget(image: BufferedImage): ByteArray? {
        val writer = ImageIO.getImageWritersByFormatName("jpg").next()
        try {
            var quality = 0.85f
            repeat(6) {
                val out = ByteArrayOutputStream()
                ImageIO.createImageOutputStream(out).use { imageOutputStream ->
                    writer.output = imageOutputStream
                    val param = writer.defaultWriteParam.apply {
                        compressionMode = ImageWriteParam.MODE_EXPLICIT
                        compressionQuality = quality
                    }
                    writer.write(null, IIOImage(image, null, null), param)
                }
                val bytes = out.toByteArray()
                if (bytes.size <= PREVIEW_TARGET_MAX_SIZE_BYTES) return bytes
                quality -= 0.15f
            }
            return null
        } finally {
            writer.dispose()
        }
    }
}
