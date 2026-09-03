@main def main(): Unit = {
  importCpg("__VULSOR_CPG_PATH__", "vulsor_b1", true)

  def clean(value: String): String = {
    value
      .replace("\t", " ")
      .replace("\r", " ")
      .replace("\n", " ")
  }

  println("VULSOR_CPG_BEGIN")

  cpg.method.map { method =>
    val line = method.lineNumber.map(_.toString).getOrElse("")
    val lineEnd = method.lineNumberEnd.map(_.toString).getOrElse("")
    List(
      "METHOD",
      clean(method.name),
      clean(method.fullName),
      clean(method.filename),
      line,
      lineEnd
    ).mkString("\t")
  }.l.foreach(println)

  cpg.call.map { call =>
    val line = call.lineNumber.map(_.toString).getOrElse("")
    val column = call.columnNumber.map(_.toString).getOrElse("")
    val callerMethod = call.method
    val methodName = callerMethod.name
    val filename = callerMethod.filename
    List(
      "CALL",
      clean(methodName),
      clean(call.name),
      clean(call.methodFullName),
      clean(call.dispatchType),
      clean(call.code),
      clean(filename),
      line,
      column
    ).mkString("\t")
  }.l.foreach(println)

  println("VULSOR_CPG_END")
}
