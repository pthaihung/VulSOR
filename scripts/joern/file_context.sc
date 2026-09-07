import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.util.control.NonFatal
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import ujson.*

@main def exec(cpgFile: String, sourceFile: String, startLine: Int, endLine: Int, outFile: String): Unit = {
  importCpg(cpgFile)
  val normalized = sourceFile.replace('\\', '/')
  val sourceLabel = Paths.get(sourceFile).getFileName.toString.replace('\\', '/')
  val sourceLines = Files.readAllLines(Paths.get(sourceFile), StandardCharsets.UTF_8).toArray(new Array[String](0)).toList
  def line(n: AstNode): Int = n.lineNumber.getOrElse(0)
  def normalizedPath(value: String): String = value.replace('\\', '/')
  def sameSourceFile(value: String): Boolean = {
    val candidate = normalizedPath(value)
    candidate == normalized || candidate.endsWith("/" + normalized) || normalized.endsWith("/" + candidate)
  }
  def file(n: AstNode): String = {
    val value = n match {
      case m: Method => normalizedPath(m.filename)
      case _ => n.astParentOption.map(file).getOrElse(sourceLabel)
    }
    if (sameSourceFile(value)) sourceLabel else value
  }
  def enclosingMethod(n: AstNode): Option[Method] = n match {
    case m: Method => Some(m)
    case _ => n.astParentOption.flatMap(enclosingMethod)
  }
  def methodName(n: AstNode): String = enclosingMethod(n).map(_.name).getOrElse("")
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
  def controlCondition(n: AstNode): String = n match {
    case c: ControlStructure =>
      try c.condition.code.headOption.getOrElse(code(c)) catch { case NonFatal(_) => code(c) }
    case _ => code(n)
  }
  def write(status: String, methodName: String = "", families: Map[String, List[Value]] = Map.empty, candidates: List[Method] = Nil,
    targetStartLine: Int = startLine, targetEndLine: Int = endLine): Unit = {
    val out = Obj("target_status" -> Str(status), "target_function" -> Str(methodName))
    out("target_start_line") = Num(targetStartLine.toDouble)
    out("target_end_line") = Num(targetEndLine.toDouble)
    out("candidates") = Arr.from(candidates.map(m => item("name" -> Str(m.name), "file" -> Str(m.filename), "start_line" -> Num(m.lineNumber.getOrElse(0).toDouble), "end_line" -> Num(m.lineNumberEnd.getOrElse(0).toDouble))))
    List("imports", "callee_funcs", "call_relations", "call_site_arguments", "data_flow",
      "control_dependencies", "declarations", "types").foreach(k => out(k) = Arr.from(families.getOrElse(k, Nil)))
    Files.writeString(Paths.get(outFile), out.render(), StandardCharsets.UTF_8)
  }
  val namedCandidates = cpg.method.filterNot(m => m.name == "<global>" || m.name == "<module>").filter { m =>
    sameSourceFile(m.filename)
  }.filter { m => m.lineNumber.exists(_ <= startLine) && m.lineNumberEnd.exists(_ >= endLine) }.toList
  val globalCandidates = cpg.method.filter { m =>
    (m.name == "<global>" || m.name == "<module>") && sameSourceFile(m.filename)
  }.filter { m => m.lineNumber.exists(_ <= startLine) && m.lineNumberEnd.exists(_ >= endLine) }.toList
  val sourceFallback = namedCandidates.isEmpty && globalCandidates.nonEmpty
  val candidates = if (namedCandidates.nonEmpty) namedCandidates else globalCandidates
  if (candidates.isEmpty) { write("not_found"); return }
  val ordered = candidates.sortBy(m => m.lineNumberEnd.getOrElse(Int.MaxValue) - m.lineNumber.getOrElse(0))
  if (ordered.size > 1 && (ordered(0).lineNumberEnd.getOrElse(Int.MaxValue) - ordered(0).lineNumber.getOrElse(0)) ==
      (ordered(1).lineNumberEnd.getOrElse(Int.MaxValue) - ordered(1).lineNumber.getOrElse(0))) {
    write("ambiguous", candidates = ordered.take(4)); return
  }
  val method = ordered.head
  val sourceCallPattern = """\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)""".r
  val sourceControlNames = Set("if", "else", "for", "while", "switch", "catch", "sizeof")
  val sourceFunctionDeclPattern = """^\s*[A-Za-z_][A-Za-z0-9_:<>*&\s]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(""".r
  val sourceTargetDeclaration = sourceLines.zipWithIndex.collectFirst {
    case (text, index) if index + 1 >= startLine && index + 1 <= endLine && sourceFunctionDeclPattern.findFirstMatchIn(text).nonEmpty =>
      (sourceFunctionDeclPattern.findFirstMatchIn(text).get.group(1), index + 1)
  }
  val sourceTargetName = sourceTargetDeclaration.map(_._1).getOrElse(method.name)
  val selectedStartLine = if (sourceFallback) sourceTargetDeclaration.map(_._2).getOrElse(startLine) else startLine
  def inSelectedRange(n: AstNode): Boolean = line(n) >= selectedStartLine && line(n) <= endLine
  val methodNameForContext = if (sourceFallback) sourceTargetName else method.name
  val imports = sourceLines.zipWithIndex.collect {
    case (text, index) if text.trim.startsWith("#include") || text.trim.startsWith("import ") =>
      item("code" -> Str(text.trim), "file" -> Str(sourceLabel), "line" -> Num((index + 1).toDouble), "provenance" -> Str("source_include"))
  }
  val declarationNodes = (method.parameter ++ method.local).filter(n => !sourceFallback || inSelectedRange(n)).toList
  val cpgDeclarations = declarationNodes.flatMap { n =>
    val t = n match { case x: MethodParameterIn => x.typeFullName; case x: Local => x.typeFullName }
    sourceItem(n, "name" -> Str(n.name), "type" -> Str(t), "provenance" -> Str("cpg_declaration"))
  }.toList
  val sourceFallbackDeclarations: List[Value] = if (!sourceFallback) Nil else {
    val header = sourceLines.slice(selectedStartLine - 1, math.min(endLine, sourceLines.size)).mkString(" ").split("\\{", 2).head
    val open = header.indexOf("(")
    val close = header.lastIndexOf(")")
    if (open < 0 || close <= open) Nil
    else header.substring(open + 1, close).split(",").toList.zipWithIndex.flatMap { case (raw, index) =>
      val cleaned = raw.replaceAll("/\\*.*?\\*/", "").trim
      if (cleaned.isEmpty || cleaned == "void") Nil
      else {
        val namePattern = """([A-Za-z_][A-Za-z0-9_]*)\s*$""".r
        namePattern.findFirstMatchIn(cleaned).map { matched =>
          val name = matched.group(1)
          val typeName = cleaned.substring(0, matched.start(1)).trim
          item("code" -> Str(cleaned), "file" -> Str(sourceLabel), "line" -> Num(selectedStartLine.toDouble),
            "name" -> Str(name), "type" -> Str(typeName), "argument_index" -> Num(index.toDouble),
            "provenance" -> Str("source_declaration_fallback"))
        }.toList
      }
    }
  }
  val declarations = cpgDeclarations ++ sourceFallbackDeclarations
  // Materialize once: Joern traversals are iterator-backed and reusing a
  // lazy traversal after callRelations can silently empty later families.
  val calls = method.call.filterNot(_.name.startsWith("<operator")).filter(c => !sourceFallback || inSelectedRange(c)).toList
  val callRelations = calls.flatMap { c => sourceItem(c, "caller" -> Str(methodNameForContext), "callee" -> Str(c.name), "provenance" -> Str("cpg_call")) }.toList
  def argumentItem(argument: AstNode, call: Call, index: Int): Option[Value] = {
    val argumentLine = if (line(argument) > 0) line(argument) else line(call)
    val argumentFile = if (line(argument) > 0) file(argument) else file(call)
    val argumentCode = code(argument)
    if (argumentLine > 0 && argumentCode.nonEmpty) Some(item(
      "code" -> Str(argumentCode), "file" -> Str(argumentFile), "line" -> Num(argumentLine.toDouble),
      "call" -> Str(call.name), "argument_index" -> Num(index.toDouble),
      "provenance" -> Str("cpg_call_argument"))) else None
  }
  val arguments = calls.flatMap { c => c.argument.toList.zipWithIndex.flatMap { case (a, i) =>
    argumentItem(a, c, i)
  }}.toList
  val callees = calls.flatMap { c => c.callee.toList.collect { case m: Method if sameSourceFile(m.filename) && !code(m).trim.startsWith("#define") =>
    item("code" -> Str(code(m)), "name" -> Str(m.name), "signature" -> Str(m.signature),
      "file" -> Str(sourceLabel), "line" -> Num(line(m).toDouble),
      "start_line" -> Num(line(m).toDouble), "end_line" -> Num(m.lineNumberEnd.getOrElse(line(m)).toDouble),
      "provenance" -> Str("cpg_same_file_callee"))
  }}.toList

  val knownCallKeys = calls.map(c => (c.name, line(c))).toSet
  val sourceCallFallbacks = sourceLines.zipWithIndex.flatMap { case (text, index) =>
    val currentLine = index + 1
    if (currentLine < selectedStartLine || currentLine > endLine) Nil
    else sourceCallPattern.findAllMatchIn(text).toList.flatMap { matched =>
      val name = matched.group(1)
      val expression = matched.group(0).trim
      val arguments = matched.group(2).split(",").toList.map(_.trim).filter(_.nonEmpty)
      if (name == methodNameForContext
          || currentLine == method.lineNumber.getOrElse(-1)
          || sourceControlNames.contains(name)
          || knownCallKeys.contains((name, currentLine))) Nil
      else List((name, expression, arguments, currentLine))
    }
  }
  val sourceCallRelations = sourceCallFallbacks.map { case (name, expression, _, currentLine) =>
    item("code" -> Str(expression), "file" -> Str(sourceLabel), "line" -> Num(currentLine.toDouble),
      "caller" -> Str(methodNameForContext), "callee" -> Str(name), "provenance" -> Str("source_call_fallback"))
  }
  val sourceCallArguments = sourceCallFallbacks.flatMap { case (name, _, arguments, currentLine) =>
    arguments.zipWithIndex.map { case (argument, index) =>
      item("code" -> Str(argument), "file" -> Str(sourceLabel), "line" -> Num(currentLine.toDouble),
        "call" -> Str(name), "argument_index" -> Num(index.toDouble),
        "provenance" -> Str("source_call_fallback"))
    }
  }
  val assignments = method.call.filter(_.name.startsWith("<operator>.assignment")).filter(a => !sourceFallback || inSelectedRange(a)).flatMap { a =>
    sourceItem(a, "defines" -> Arr.from(a.argument.headOption.toList.flatMap(ids).map(Str(_))),
      "uses" -> Arr.from(a.argument.drop(1).flatMap(ids).map(Str(_))), "provenance" -> Str("syntactic_assignment"))
  }.toList
  val dataFlow = try {
    if (!cpg.metaData.headOption.exists(_.overlays.contains("ossdataflow"))) run.ossdataflow
    val flowSources = declarationNodes
    val flowSinks: Iterator[CfgNode] = calls.iterator.flatMap(_.argument).map(x => x: CfgNode)
    flowSinks.reachableByFlows(flowSources).take(80).flatMap { path =>
      path.elements.toList.collect { case n: AstNode => n }.sliding(2).flatMap {
        case List(from, to) if line(from) > 0 && line(to) > 0 && code(from).nonEmpty && code(to).nonEmpty &&
            (!sourceFallback || (inSelectedRange(from) && inSelectedRange(to))) =>
          Some(item("code" -> Str(code(from) + " -> " + code(to)), "file" -> Str(file(to)),
            "line" -> Num(line(to).toDouble), "from_line" -> Num(line(from).toDouble),
            "from_file" -> Str(file(from)), "from_method" -> Str(methodName(from)),
            "to_method" -> Str(methodName(to)),
            "defines" -> Arr.from(ids(to).map(Str(_))), "uses" -> Arr.from(ids(from).map(Str(_))),
            "provenance" -> Str("joern_reaching_def")))
        case _ => None
      }
    }.toList
  } catch { case NonFatal(_) => Nil }
  val controls = method.ast.isControlStructure.filter(c => !sourceFallback || inSelectedRange(c)).flatMap { c =>
    val condition = controlCondition(c)
    if (condition.nonEmpty) sourceItem(c, "condition" -> Str(condition), "provenance" -> Str("cpg_control")) else None
  }.toList
  val types = declarations.flatMap(v => List(v("type").str)).filter(_.nonEmpty).distinct.sorted.map(t => item("name" -> Str(t), "provenance" -> Str("cpg_type")))
  val controlledCalls = calls.flatMap { call =>
    try call.controlledBy.flatMap { guard =>
      sourceItem(guard, "condition" -> Str(controlCondition(guard)),
        "controlled_line" -> Num(line(call).toDouble), "provenance" -> Str("joern_control_dependence"))
    }.toList catch { case NonFatal(_) => Nil }
  }.toList
  write("exact", methodNameForContext, Map(
    "imports" -> imports, "callee_funcs" -> callees,
    "call_site_arguments" -> (arguments ++ sourceCallArguments),
    "call_relations" -> (callRelations ++ sourceCallRelations),
    "data_flow" -> (dataFlow ++ assignments), "control_dependencies" -> (controls ++ controlledCalls),
    "declarations" -> declarations, "types" -> types),
    targetStartLine = if (sourceFallback) selectedStartLine else method.lineNumber.getOrElse(startLine),
    targetEndLine = if (sourceFallback) endLine else method.lineNumberEnd.getOrElse(endLine))
}
