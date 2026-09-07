import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.util.control.NonFatal
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import ujson.*

@main def exec(cpgFile: String, sourceFile: String, startLine: Int, endLine: Int, outFile: String): Unit = {
  importCpg(cpgFile)
  val normalized = sourceFile.replace('\\', '/')
  val sourceLines = Files.readAllLines(Paths.get(sourceFile), StandardCharsets.UTF_8).toArray(new Array[String](0)).toList
  def line(n: AstNode): Int = n.lineNumber.getOrElse(0)
  def file(n: AstNode): String = n match {
    case m: Method => m.filename.replace('\\', '/')
    case _ => n.astParentOption.map(file).getOrElse(normalized)
  }
  def code(n: AstNode): String = Option(n.code).getOrElse("").trim
  def ids(n: AstNode): List[String] = n.ast.isIdentifier.name.toList.filter(_.nonEmpty).distinct
  def item(fields: (String, Value)*): Value = {
    val result = Obj()
    fields.foreach { case (key, value) => result(key) = value }
    result
  }
  def sourceItem(n: AstNode, fields: (String, Value)*): Option[Value] =
    if (line(n) > 0 && code(n).nonEmpty) Some(item(
      (List("code" -> Str(code(n)), "file" -> Str(file(n)), "line" -> Num(line(n).toDouble)) ++ fields.toList): _*)) else None
  def write(status: String, methodName: String = "", families: Map[String, List[Value]] = Map.empty, candidates: List[Method] = Nil): Unit = {
    val out = Obj("target_status" -> Str(status), "target_function" -> Str(methodName))
    out("candidates") = Arr.from(candidates.map(m => item("name" -> Str(m.name), "file" -> Str(m.filename), "start_line" -> Num(m.lineNumber.getOrElse(0).toDouble), "end_line" -> Num(m.lineNumberEnd.getOrElse(0).toDouble))))
    List("imports", "callee_funcs", "call_relations", "call_site_arguments", "data_flow",
      "control_dependencies", "declarations", "types").foreach(k => out(k) = Arr.from(families.getOrElse(k, Nil)))
    Files.writeString(Paths.get(outFile), out.render(), StandardCharsets.UTF_8)
  }
  val candidates = cpg.method.filter { m =>
    val f = m.filename.replace('\\', '/')
    f == normalized || f.endsWith("/" + normalized) || normalized.endsWith("/" + f)
  }.filter { m => m.lineNumber.exists(_ <= startLine) && m.lineNumberEnd.exists(_ >= endLine) }.toList
  if (candidates.isEmpty) { write("not_found"); return }
  val ordered = candidates.sortBy(m => m.lineNumberEnd.getOrElse(Int.MaxValue) - m.lineNumber.getOrElse(0))
  if (ordered.size > 1 && (ordered(0).lineNumberEnd.getOrElse(Int.MaxValue) - ordered(0).lineNumber.getOrElse(0)) ==
      (ordered(1).lineNumberEnd.getOrElse(Int.MaxValue) - ordered(1).lineNumber.getOrElse(0))) {
    write("ambiguous", candidates = ordered.take(4)); return
  }
  val method = ordered.head
  val imports = sourceLines.zipWithIndex.collect {
    case (text, index) if text.trim.startsWith("#include") || text.trim.startsWith("import ") =>
      item("code" -> Str(text.trim), "file" -> Str(normalized), "line" -> Num((index + 1).toDouble), "provenance" -> Str("source_include"))
  }
  val declarations = (method.parameter ++ method.local).flatMap { n =>
    val t = n match { case x: MethodParameterIn => x.typeFullName; case x: Local => x.typeFullName }
    sourceItem(n, "name" -> Str(n.name), "type" -> Str(t), "provenance" -> Str("cpg_declaration"))
  }.toList
  val calls = method.call.filterNot(_.name.startsWith("<operator"))
  val callRelations = calls.flatMap { c => sourceItem(c, "caller" -> Str(method.name), "callee" -> Str(c.name), "provenance" -> Str("cpg_call")) }.toList
  val arguments = calls.flatMap { c => c.argument.toList.zipWithIndex.flatMap { case (a, i) =>
    sourceItem(a, "call" -> Str(c.name), "argument_index" -> Num(i.toDouble), "provenance" -> Str("cpg_call_argument"))
  }}.toList
  val callees = calls.flatMap { c => c.callee.toList.collect { case m: Method if m.filename.replace('\\', '/') == normalized =>
    item("name" -> Str(m.name), "signature" -> Str(m.signature), "file" -> Str(normalized), "line" -> Num(line(m).toDouble), "provenance" -> Str("cpg_same_file_callee"))
  }}.toList
  val assignments = method.call.filter(_.name.startsWith("<operator>.assignment")).flatMap { a =>
    sourceItem(a, "defines" -> Arr.from(a.argument.headOption.toList.flatMap(ids).map(Str(_))),
      "uses" -> Arr.from(a.argument.drop(1).flatMap(ids).map(Str(_))), "provenance" -> Str("syntactic_assignment"))
  }.toList
  val controls = method.ast.isControlStructure.flatMap { c =>
    val condition = try c.condition.code.headOption.getOrElse(code(c)) catch { case NonFatal(_) => code(c) }
    if (condition.nonEmpty) sourceItem(c, "condition" -> Str(condition), "provenance" -> Str("cpg_control")) else None
  }.toList
  val types = declarations.flatMap(v => List(v("type").str)).filter(_.nonEmpty).distinct.sorted.map(t => item("name" -> Str(t), "provenance" -> Str("cpg_type")))
  write("exact", method.name, Map(
    "imports" -> imports, "callee_funcs" -> callees, "call_relations" -> callRelations,
    "call_site_arguments" -> arguments, "data_flow" -> assignments, "control_dependencies" -> controls,
    "declarations" -> declarations, "types" -> types))
}
