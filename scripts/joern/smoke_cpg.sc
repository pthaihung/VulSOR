import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import ujson.*

@main def exec(cpgFile: String, outFile: String): Unit = {
  importCpg(cpgFile)
  val result = ujson.Obj(
    "methodCount" -> cpg.method.l.size,
    "callCount" -> cpg.call.l.size,
    "fileCount" -> cpg.file.l.size
  )
  Files.writeString(Paths.get(outFile), ujson.write(result), StandardCharsets.UTF_8)
}
