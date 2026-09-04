import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import ujson.*

@main def exec(cpgFile: String, outFile: String): Unit =
  importCpg(cpgFile)
  val result = Obj(
    "methodCount" -> cpg.method.size,
    "callCount" -> cpg.call.size,
    "fileCount" -> cpg.file.size,
  )
  Files.writeString(Paths.get(outFile), result.render(), StandardCharsets.UTF_8)
