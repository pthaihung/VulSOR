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
  val limitations = Arr()
  var truncated = false

  def line(node: AstNode): Value = node.lineNumber.map(value => Num(value.toDouble)).getOrElse(Null)
  def source(code: String, file: String, node: AstNode, anchorLine: Option[Int] = None): Value = {
    val value = Obj("code" -> Str(code), "file" -> Str(file), "line" -> line(node))
    anchorLine.foreach(lineNumber => value("anchor_line") = Num(lineNumber.toDouble))
    value
  }
  def sourceAt(code: String, file: String, lineNumber: Int): Value =
    Obj("code" -> Str(code), "file" -> Str(file), "line" -> Num(lineNumber.toDouble))
  def bounded(values: List[Value], limit: Int, family: String): Arr = {
    val unique = values.foldLeft(List.empty[Value]) { (retained, value) =>
      if (retained.exists(_.render() == value.render())) retained else retained :+ value
    }
    if (unique.size > limit) {
      truncated = true
      limitations.value += Str(s"$family: bounded to $limit items")
    }
    Arr.from(unique.take(limit))
  }
  def write(status: String, anchors: Arr = Arr(), data: Arr = Arr(), controls: Arr = Arr(),
            declarations: Arr = Arr(), contracts: Arr = Arr(), calls: Arr = Arr()): Unit = {
    val output = Obj(
      "anchor_status" -> Str(status),
      "anchors" -> anchors,
      "data_dependencies" -> data,
      "control_dependencies" -> controls,
      "declarations_types" -> declarations,
      "local_contracts" -> contracts,
      "calls" -> calls,
      "limitations" -> limitations,
      "truncated" -> Bool(truncated)
    )
    Files.writeString(Paths.get(outFile), output.render(), StandardCharsets.UTF_8)
  }
  def entityOf(code: String): Option[String] =
    """\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*$""".r.findFirstMatchIn(code).map(_.group(1))
  def isFloatingPointPointerCastDereference(code: String): Boolean =
    """\*\s*\(\s*(?:float|double)\s*\*\s*\)""".r.findFirstIn(code).nonEmpty
  def macroContract(root: String, anchors: List[Call], entities: Set[String]): List[Value] = {
    val sourcePath = Paths.get(root).resolve(requestedFile).normalize
    if (!Files.isRegularFile(sourcePath)) return Nil
    val sourceLines = Files.readAllLines(sourcePath, StandardCharsets.UTF_8).toArray(new Array[String](0)).toList
    val macroNames = anchors.flatMap { anchor =>
      anchor.lineNumber.flatMap(lineNumber => sourceLines.lift(lineNumber - 1)).toList.flatMap { sourceLine =>
        """([A-Za-z_][A-Za-z0-9_]*)\s*\(""".r.findAllMatchIn(sourceLine).map(_.group(1))
      }
    }.distinct
    macroNames.flatMap { name =>
      val start = sourceLines.indexWhere(_.trim.startsWith(s"#define $name"))
      if (start < 0) Nil
      else {
        val body = ListBuffer.empty[String]
        var offset = start
        var continues = true
        while (offset < sourceLines.size && (offset == start || continues)) {
          val current = sourceLines(offset)
          body += current
          continues = current.trim.endsWith("\\")
          offset += 1
        }
        val relevant = body.filter { current =>
          current.contains(name) ||
            (entities.exists(entity => current.matches(s".*\\b${java.util.regex.Pattern.quote(entity)}\\b.*")) &&
              (current.contains("=") || current.contains("for") || current.contains("+=") ||
                entities.exists(entity => current.contains(s"*$entity"))))
        }
        if (relevant.nonEmpty) List(sourceAt(relevant.mkString("\n"), requestedFile, start + 1)) else Nil
      }
    }
  }

  val candidates = cpg.method.nameExact(requestedName)
    .filter(method => {
      val normalized = method.filename.replace('\\', '/')
      normalized == requestedFile || normalized.endsWith("/" + requestedFile)
    }).take(2).toList
  if (candidates.isEmpty) { write("not_found"); return }
  if (candidates.size > 1) { write("ambiguous"); return }
  val method = candidates.head
  val file = method.filename.replace('\\', '/')
  val pointerCastDereferences = method.call
    .filter(call => call.name == "<operator>.indirection")
    .filter(call => entityOf(call.code).nonEmpty)
    .sortBy(_.lineNumber.getOrElse(Int.MaxValue))
    .toList
  val anchors = (
    pointerCastDereferences.filter(call => isFloatingPointPointerCastDereference(call.code)) ++
      pointerCastDereferences.filterNot(call => isFloatingPointPointerCastDereference(call.code))
    ).take(2)
  if (anchors.isEmpty) {
    limitations.value += Str("no_risk_anchor_found")
    write("exact")
    return
  }

  val anchorValues = Arr.from(anchors.map(anchor => source(anchor.code, file, anchor)))
  val entities = anchors.flatMap(anchor => entityOf(anchor.code)).toSet
  val dataValues = anchors.flatMap { anchor =>
    val anchorLine = anchor.lineNumber.getOrElse(0)
    entityOf(anchor.code).toList.map(entity => source(s"$entity -> ${anchor.code}", file, anchor, Some(anchorLine)))
  }
  val declarations = (method.parameter ++ method.local)
    .filter(node => entities.contains(node.name))
    .map { node =>
      val typeName = node match {
        case local: Local => local.typeFullName
        case parameter: MethodParameterIn => parameter.typeFullName
      }
      Obj("code" -> Str(s"${node.name}: $typeName"), "name" -> Str(node.name), "type" -> Str(typeName),
        "file" -> Str(file), "line" -> line(node))
    }.toList.groupBy(item => (item("name").str, item("type").str)).values.map(_.head).toList
  val contracts = request.obj.get("source_root").map(_.str).toList.flatMap(root => macroContract(root, anchors, entities))
  val controls = anchors.flatMap { anchor =>
    val anchorLine = anchor.lineNumber.getOrElse(0)
    try anchor.inAst.isControlStructure
      .filter(control => control.code.length <= 300)
      .filter(control => entities.exists(entity => control.code.matches(s".*\\b${java.util.regex.Pattern.quote(entity)}\\b.*")))
      .map(control => source(control.code, file, control, Some(anchorLine))).toList
    catch { case NonFatal(_) => Nil }
  }
  val calls = method.call
    .filter(call => !call.name.startsWith("<operator"))
    .filter(call => anchors.exists(anchor => call.lineNumber == anchor.lineNumber))
    .filter(call => entities.exists(entity => call.code.matches(s".*\\b${java.util.regex.Pattern.quote(entity)}\\b.*")))
    .map { call =>
      Obj("code" -> Str(call.code), "callee" -> Str(call.name),
        "arguments" -> Arr.from(call.argument.map(argument => Str(argument.code)).toList),
        "file" -> Str(file), "line" -> line(call))
    }.toList
  val boundedData = bounded(dataValues, 16, "data_dependencies")
  val boundedControls = bounded(controls, 20, "control_dependencies")
  val boundedDeclarations = bounded(declarations, 12, "declarations_types")
  val boundedContracts = bounded(contracts, 2, "local_contracts")
  val boundedCalls = bounded(calls, 12, "calls")
  if (boundedData.value.isEmpty) limitations.value += Str("data_dependencies: no mapped evidence was found")
  if (boundedControls.value.isEmpty) limitations.value += Str("control_dependencies: no mapped evidence was found")
  if (boundedDeclarations.value.isEmpty) limitations.value += Str("declarations_types: no mapped evidence was found")
  if (boundedContracts.value.isEmpty) limitations.value += Str("local_contracts: no mapped evidence was found")
  if (boundedCalls.value.isEmpty) limitations.value += Str("calls: no mapped evidence was found")
  write("exact", anchorValues, boundedData, boundedControls, boundedDeclarations, boundedContracts, boundedCalls)
}
