import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.collection.mutable.ListBuffer
import scala.util.control.NonFatal
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import ujson.*

@main def exec(cpgFile: String, requestFile: String, outFile: String): Unit = {
  importCpg(cpgFile)
  val request = ujson.read(Files.readString(Paths.get(requestFile), StandardCharsets.UTF_8))
  val requestedFile = request("file_path").str.replace('\\', '/')
  val requestedName = request("function_name").str
  val maxItems = request.obj.get("max_items").map(_.num.toInt).getOrElse(120)
  val limitations = Arr()
  var truncated = false

  def names(values: Iterable[String]): Arr =
    Arr.from(values.filter(_.nonEmpty).toList.distinct.sorted.map(Str(_)))
  def identifiers(node: AstNode): List[String] =
    node.ast.isIdentifier.name.toList.filter(_.nonEmpty).distinct
  def conditionIdentifiers(control: ControlStructure): List[String] =
    try control.condition.ast.isIdentifier.name.toList.filter(_.nonEmpty).distinct
    catch { case NonFatal(_) => identifiers(control) }
  def line(node: AstNode): Option[Int] = node.lineNumber.filter(_ > 0)
  def owner(node: AstNode): Option[Method] = {
    var current = node.astParentOption
    while (current.nonEmpty && !current.get.isInstanceOf[Method]) current = current.get.astParentOption
    current.collect { case method: Method => method }
  }
  def fileOf(node: AstNode): String = owner(node)
    .map(_.filename.replace('\\', '/')).getOrElse(requestedFile)
  def candidate(node: AstNode, code: String, defines: Iterable[String], uses: Iterable[String],
                provenance: String, extra: (String, Value)*): Option[Value] =
    line(node).filter(_ => code.trim.nonEmpty).map { lineNumber =>
      val value = Obj("code" -> Str(code.trim), "file" -> Str(fileOf(node)),
        "line" -> Num(lineNumber.toDouble), "provenance" -> Str(provenance),
        "defines" -> names(defines), "uses" -> names(uses))
      extra.foreach { case (key, item) => value(key) = item }
      value
    }
  def sourceCandidate(code: String, lineNumber: Int, defines: Iterable[String],
                      uses: Iterable[String], provenance: String,
                      extra: (String, Value)*): Value = {
    val value = Obj("code" -> Str(code.trim), "file" -> Str(requestedFile),
      "line" -> Num(lineNumber.toDouble), "provenance" -> Str(provenance),
      "defines" -> names(defines), "uses" -> names(uses))
    extra.foreach { case (key, item) => value(key) = item }
    value
  }
  def bounded(values: List[Value], family: String): Arr = {
    val unique = values.foldLeft(List.empty[Value]) { (retained, value) =>
      if (retained.exists(_.render() == value.render())) retained else retained :+ value
    }
    if (unique.size > maxItems) {
      truncated = true
      limitations.value += Str(s"$family: candidate pool bounded to $maxItems items")
    }
    Arr.from(unique.take(maxItems))
  }
  def write(status: String, seeds: Arr = Arr(), data: Arr = Arr(), controls: Arr = Arr(),
            declarations: Arr = Arr(), contracts: Arr = Arr(), calls: Arr = Arr()): Unit = {
    val output = Obj("target_status" -> Str(status), "seeds" -> seeds,
      "data_candidates" -> data, "control_candidates" -> controls,
      "declaration_candidates" -> declarations, "contract_candidates" -> contracts,
      "call_candidates" -> calls, "limitations" -> limitations, "truncated" -> Bool(truncated))
    Files.writeString(Paths.get(outFile), output.render(), StandardCharsets.UTF_8)
  }
  def sensitive(name: String): Boolean = {
    val lowered = name.toLowerCase
    List("memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "malloc",
      "calloc", "realloc", "free", "read", "recv", "parse", "decode", "convert")
      .exists(lowered.contains)
  }
  def riskArithmetic(call: Call): Boolean = {
    val lowered = call.code.toLowerCase
    Set("<operator>.addition", "<operator>.subtraction", "<operator>.multiplication",
      "<operator>.indexaccess").contains(call.name.toLowerCase) &&
      List("size", "length", "count", "offset", "index", "bytes", "components", "format")
        .exists(lowered.contains)
  }
  def controlRole(code: String): String = {
    val lowered = code.toLowerCase
    if (lowered.contains("null")) "null_check"
    else if ((lowered.contains("+") || lowered.contains("*")) &&
      (lowered.contains("<") || lowered.contains(">")) &&
      List("size", "length", "offset", "bytes", "count").exists(lowered.contains)) "overflow_check"
    else if ((lowered.contains("<") || lowered.contains(">") || lowered.contains("==")) &&
      List("size", "length", "offset", "index", "bytes", "count", "components", "format", "exif", "end").exists(lowered.contains)) "bounds_check"
    else if (lowered.contains("switch") || lowered.contains("format") || lowered.contains("type")) "type_or_format_dispatch"
    else if (lowered.contains("for") || lowered.contains("while") || lowered.contains("do")) "loop_bound"
    else "other_guard"
  }
  def macroContracts(root: String, method: Method): List[Value] = {
    val sourcePath = Paths.get(root).resolve(requestedFile).normalize
    if (!Files.isRegularFile(sourcePath)) return Nil
    val sourceLines = Files.readAllLines(sourcePath, StandardCharsets.UTF_8)
      .toArray(new Array[String](0)).toList
    val invoked = method.call.name.toSet
    sourceLines.zipWithIndex.flatMap { case (sourceLine, index) =>
      val macroName = """^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(""".r
        .findFirstMatchIn(sourceLine).map(_.group(1))
      macroName.filter(invoked.contains).toList.flatMap { name =>
        val invocationLines = method.call.nameExact(name).lineNumber.toList.distinct.sorted
        val body = ListBuffer(sourceLine)
        var offset = index + 1
        var continues = sourceLine.trim.endsWith("\\")
        while (offset < sourceLines.size && continues && body.size < 40) {
          val current = sourceLines(offset)
          body += current
          continues = current.trim.endsWith("\\")
          offset += 1
        }
        val relevant = body.filter(current => current.contains(name) || current.contains("=") ||
          current.contains("+=") || current.contains("-=") || current.contains("for") || current.contains("if"))
        val foundNames = """[A-Za-z_][A-Za-z0-9_]*""".r
          .findAllIn(relevant.mkString(" ")).toList
          .filterNot(Set("define", "if", "for", "while", "return", name))
        if (relevant.nonEmpty) List(sourceCandidate(relevant.mkString("\n"), index + 1,
          foundNames, foundNames, "repository_source_macro", "name" -> Str(name),
          "invocation_lines" -> Arr.from(invocationLines.map(value => Num(value.toDouble))))) else Nil
      }
    }
  }

  val methods = cpg.method.nameExact(requestedName).filter { method =>
    val normalized = method.filename.replace('\\', '/')
    normalized == requestedFile || normalized.endsWith("/" + requestedFile)
  }.take(2).toList
  if (methods.isEmpty) { write("not_found"); return }
  if (methods.size > 1) { write("ambiguous"); return }
  val method = methods.head

  val seedValues = method.call.flatMap { call =>
    val pointerCast = call.name == "<operator>.indirection" && call.code.contains("*)")
    val floatingPointerCast = pointerCast &&
      """\*\s*\(\s*(?:float|double)\s*\*\s*\)""".r.findFirstIn(call.code).nonEmpty
    val indexed = call.name.equalsIgnoreCase("<operator>.indexAccess")
    val isSensitive = !call.name.startsWith("<operator") && sensitive(call.name)
    val priority = if (floatingPointerCast) 110 else if (pointerCast) 100 else if (indexed) 90 else if (isSensitive) 80
      else if (riskArithmetic(call)) 70 else 0
    if (priority == 0) None
    else candidate(call, call.code, Nil, identifiers(call), "cpg_ast",
      "priority" -> Num(priority.toDouble))
  }.toList.sortBy(value => (-value("priority").num.toInt, value("line").num.toInt))

  val assignmentValues = method.call.filter(_.name.startsWith("<operator>.assignment")).flatMap { assignment =>
    val arguments = assignment.argument.toList
    val defines = arguments.headOption.toList.flatMap(identifiers)
    val uses = arguments.drop(1).flatMap(identifiers)
    candidate(assignment, assignment.code, defines, uses, "syntactic_assignment_fallback",
      "kind" -> Str("assignment"))
  }.toList
  val parameterValues = method.parameter.flatMap(parameter =>
    candidate(parameter, parameter.code, List(parameter.name), Nil, "cpg_ast",
      "kind" -> Str("parameter"))).toList
  val returnValues = method.ast.isReturn.flatMap(result =>
    candidate(result, result.code, Nil, identifiers(result), "cpg_ast",
      "kind" -> Str("return"))).toList

  val controlValues = method.ast.isControlStructure.flatMap { control =>
    val condition = try control.condition.code.headOption.getOrElse(control.code.take(300))
      catch { case NonFatal(_) => control.code.take(300) }
    val governed = control.ast.lineNumber.toList.distinct.sorted
    candidate(control, condition, Nil, conditionIdentifiers(control), "cpg_control",
      "role" -> Str(controlRole(condition)),
      "governs_lines" -> Arr.from(governed.map(value => Num(value.toDouble))))
  }.toList

  val declarationValues = (method.parameter ++ method.local).flatMap { node =>
    val typeName = node match {
      case local: Local => local.typeFullName
      case parameter: MethodParameterIn => parameter.typeFullName
    }
    candidate(node, s"${node.name}: $typeName", List(node.name), Nil, "cpg_declaration",
      "name" -> Str(node.name), "type" -> Str(typeName))
  }.toList.groupBy(value => (value("defines").render(), value("type").str)).values.map(_.head).toList

  val contractValues = request.obj.get("source_root").map(_.str).toList.flatMap(root => macroContracts(root, method))
  val directCalls = method.call.filter(call => !call.name.startsWith("<operator")).flatMap { call =>
    candidate(call, call.code, Nil, identifiers(call), "cpg_call",
      "callee" -> Str(call.name), "arguments" -> Arr.from(call.argument.code.toList.map(Str(_))),
      "relation" -> Str("target_calls"), "sensitive" -> Bool(sensitive(call.name)))
  }.toList
  val callerCalls = method.callIn.flatMap { call =>
    candidate(call, call.code, Nil, identifiers(call), "cpg_call",
      "callee" -> Str(method.name), "arguments" -> Arr.from(call.argument.code.toList.map(Str(_))),
      "relation" -> Str("calls_target"), "sensitive" -> Bool(false))
  }.toList

  write("exact", bounded(seedValues, "seeds"),
    bounded(assignmentValues ++ parameterValues ++ returnValues, "data_candidates"),
    bounded(controlValues, "control_candidates"), bounded(declarationValues, "declaration_candidates"),
    bounded(contractValues, "contract_candidates"), bounded(directCalls ++ callerCalls, "call_candidates"))
}
