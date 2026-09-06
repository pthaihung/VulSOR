import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.collection.mutable
import scala.util.Try
import scala.util.control.NonFatal
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import ujson.*

@main def exec(cpgFile: String, requestFile: String, outFile: String): Unit = {
  importCpg(cpgFile)
  val request = ujson.read(Files.readString(Paths.get(requestFile), StandardCharsets.UTF_8))
  val requestedFile = request("file_path").str.replace('\\', '/')
  val requestedName = request("function_name").str
  val maxItems = request("max_items").num.toInt
  require(maxItems >= 1 && maxItems <= 1000)
  implicit val engineContext: EngineContext = EngineContext(config = EngineConfig(maxCallDepth = 1))
  val limitations = Arr()
  var truncated = false

  def nodeValue(node: StoredNode, file: String): Value = {
    val ast = node match { case item: AstNode => Some(item); case _ => None }
    val name = node match {
      case item: Call => Some(item.name)
      case item: Identifier => Some(item.name)
      case item: Local => Some(item.name)
      case item: MethodParameterIn => Some(item.name)
      case _ => None
    }
    val typeName = node match {
      case item: Call => Some(item.typeFullName)
      case item: Identifier => Some(item.typeFullName)
      case item: Local => Some(item.typeFullName)
      case item: MethodParameterIn => Some(item.typeFullName)
      case _ => None
    }
    Obj(
      "code" -> Str(ast.map(_.code).getOrElse("")),
      "name" -> name.map(Str(_)).getOrElse(Null),
      "type" -> typeName.map(Str(_)).getOrElse(Null),
      "file" -> Str(file),
      "line" -> ast.flatMap(_.lineNumber).map(line => Num(line.toDouble)).getOrElse(Null)
    )
  }

  def bounded(items: Iterator[Value], family: String): Arr = {
    val all = items.toList
    val unique = all.groupBy(_.render()).values.map(_.head).toList.sortBy(_.render())
    if (unique.size > maxItems) {
      truncated = true
      limitations.value += Str(s"$family: bounded to $maxItems items")
    }
    Arr.from(unique.take(maxItems))
  }

  def empty(status: String): Unit = {
    val output = Obj(
      "anchor_status" -> Str(status),
      "calls" -> Arr(),
      "data_dependencies" -> Arr(),
      "control_dependencies" -> Arr(),
      "declarations_types" -> Arr(),
      "limitations" -> limitations,
      "truncated" -> Bool(false)
    )
    Files.writeString(Paths.get(outFile), output.render(), StandardCharsets.UTF_8)
  }

  val candidates = cpg.method.nameExact(requestedName)
    .filter(method => {
      val normalized = method.filename.replace('\\', '/')
      normalized == requestedFile || normalized.endsWith("/" + requestedFile)
    }).take(2).toList
  if (candidates.isEmpty) { empty("not_found"); return }
  if (candidates.size > 1) { empty("ambiguous"); return }
  val method = candidates.head
  val file = method.filename.replace('\\', '/')

  val calls = bounded(method.call.map { call =>
    Obj(
      "code" -> Str(call.code),
      "callee" -> Str(call.name),
      "arguments" -> Arr.from(call.argument.map(argument => Str(argument.code)).toList),
      "file" -> Str(file),
      "line" -> call.lineNumber.map(line => Num(line.toDouble)).getOrElse(Null)
    )
  }, "calls")
  if (calls.value.isEmpty) limitations.value += Str("calls: no mapped evidence was found")

  val declarations = bounded((method.parameter ++ method.local).map(node => nodeValue(node, file)), "declarations_types")
  if (declarations.value.isEmpty) limitations.value += Str("declarations_types: no mapped evidence was found")

  val controls = try {
    bounded(method.call.flatMap { call =>
      call.controlledBy.map { condition =>
        Obj(
          "code" -> Str(call.code),
          "condition" -> Str(condition.code),
          "file" -> Str(file),
          "line" -> call.lineNumber.map(line => Num(line.toDouble)).getOrElse(Null)
        )
      }
    }, "control_dependencies")
  } catch {
    case NonFatal(_) =>
      limitations.value += Str("control_dependencies: graph query failed")
      Arr()
  }
  if (controls.value.isEmpty) limitations.value += Str("control_dependencies: no mapped evidence was found")

  val dataDependencies = try {
    if (!cpg.metaData.headOption.exists(_.overlays.contains("ossdataflow"))) run.ossdataflow
    val sources = method.parameter ++ method.local
    bounded(method.call.reachableByFlows(sources).map { path =>
      val nodes = path.elements.toList
      val rendered = nodes.map(node => node.code).mkString(" -> ")
      val first = nodes.headOption
      Obj(
        "code" -> Str(rendered),
        "file" -> Str(file),
        "line" -> first.flatMap(_.lineNumber).map(line => Num(line.toDouble)).getOrElse(Null)
      )
    }, "data_dependencies")
  } catch {
    case NonFatal(_) =>
      limitations.value += Str("data_dependencies: graph query failed")
      Arr()
  }
  if (dataDependencies.value.isEmpty) limitations.value += Str("data_dependencies: no mapped evidence was found")

  val output = Obj(
    "anchor_status" -> Str("exact"),
    "calls" -> calls,
    "data_dependencies" -> dataDependencies,
    "control_dependencies" -> controls,
    "declarations_types" -> declarations,
    "limitations" -> limitations,
    "truncated" -> Bool(truncated)
  )
  Files.writeString(Paths.get(outFile), output.render(), StandardCharsets.UTF_8)
}
