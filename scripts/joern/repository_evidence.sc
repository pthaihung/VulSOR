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
  val anchorSpec = request("anchor")
  val budget = request("budget")
  val maxNodes = budget("max_nodes").num.toInt
  val maxFlows = budget("max_flow_paths").num.toInt
  val maxDepth = budget("max_call_depth").num.toInt
  require(maxNodes > 0 && maxNodes <= 5000 && maxFlows > 0 && maxFlows <= 100)
  require(maxDepth > 0 && maxDepth <= 5)
  implicit val engineContext: EngineContext = EngineContext(config = EngineConfig(maxCallDepth = maxDepth))
  val families = Obj()
  val limitations = Arr()
  var truncated = false
  val usedNodes = mutable.Set.empty[Long]
  def norm(path: String): String = path.replace('\\', '/')
  def optional(key: String): Option[Value] = anchorSpec.obj.get(key).filter(_ != Null)
  def text(value: Option[String]): Value = value.map(Str(_)).getOrElse(Null)
  def number(value: Option[Int]): Value = value.map(x => Num(x.toDouble)).getOrElse(Null)
  def named(n: StoredNode): Option[String] = n match {
    case v: Call => Some(v.name)
    case v: Method => Some(v.name)
    case v: Identifier => Some(v.name)
    case v: Local => Some(v.name)
    case v: MethodParameterIn => Some(v.name)
    case v: Member => Some(v.name)
    case _ => None
  }
  def typed(n: StoredNode): Option[String] = n match {
    case v: Call => Some(v.typeFullName)
    case v: Identifier => Some(v.typeFullName)
    case v: Literal => Some(v.typeFullName)
    case v: Local => Some(v.typeFullName)
    case v: MethodParameterIn => Some(v.typeFullName)
    case v: Member => Some(v.typeFullName)
    case _ => None
  }
  def owner(n: StoredNode): Option[Method] = n match {
    case m: Method => Some(m)
    case a: AstNode => Try {
      var current = a.astParentOption
      while (current.nonEmpty && !current.get.isInstanceOf[Method]) {
        current = current.get.astParentOption
      }
      current.collect { case m: Method => m }
    }.toOption.flatten
    case _ => None
  }
  def node(n: StoredNode): Value = {
    val ast = n match { case a: AstNode => Some(a); case _ => None }
    val method = owner(n)
    val arg = n match {
      case a: Expression => Some(a.argumentIndex)
      case p: MethodParameterIn => Some(p.index)
      case _ => None
    }
    Obj("id" -> Num(n.id.toDouble), "nodeType" -> Str(n.label),
      "name" -> text(named(n)), "code" -> text(ast.map(_.code)),
      "file" -> text(method.map(m => norm(m.filename))),
      "line" -> number(ast.flatMap(_.lineNumber)), "column" -> number(ast.flatMap(_.columnNumber)),
      "method" -> text(method.map(_.name)), "typeFullName" -> text(typed(n)),
      "argumentIndex" -> number(arg))
  }
  def write(status: String, count: Int): Unit = {
    val result = Obj("schema_version" -> 1, "request_id" -> request("request_id"),
      "resolved_revision" -> request("repository_ref")("revision"),
      "anchor_resolution" -> Obj("status" -> status, "candidate_count" -> count),
      "families" -> families, "limitations" -> limitations, "truncated" -> truncated)
    Files.writeString(Paths.get(outFile), result.render(), StandardCharsets.UTF_8)
  }
  val filename = norm(anchorSpec("file_path").str)
  val candidates = cpg.method.nameExact(anchorSpec("function_name").str)
    .filter(m => norm(m.filename) == filename || norm(m.filename).endsWith("/" + filename))
    .filter(m => optional("function_signature").forall(_.str == m.signature))
    .call.nameExact(anchorSpec("operation_name").str)
    .filter(c => c.lineNumber.contains(anchorSpec("line").num.toInt))
    .filter(c => optional("column").forall(v => c.columnNumber.contains(v.num.toInt)))
    .take(2).toList
  if (candidates.isEmpty) { write("not_found", 0); return }
  if (candidates.size > 1) { write("ambiguous", candidates.size); return }
  val anchor = candidates.head
  val entity = optional("entity").map(_.str)
  def matchesEntity(n: StoredNode): Boolean = entity.exists(e => named(n).contains(e))
  def emit(out: Arr, kind: String, relation: String, n: StoredNode,
           flow: List[AstNode] = Nil): Unit = {
    val ids = (n.id :: flow.map(_.id)).toSet
    if ((usedNodes.toSet ++ ids).size > maxNodes) { truncated = true; return }
    usedNodes ++= ids
    out.value += Obj("kind" -> kind, "relation" -> relation,
      "subject" -> anchor.method.name, "object" -> text(named(n)), "conditions" -> Arr(),
      "node" -> node(n), "path" -> Arr.from(flow.map(node)))
  }
  def bounded[A](items: Iterator[A]): List[A] = {
    val found = items.take(maxNodes + 1).toList
    if (found.size > maxNodes) truncated = true
    found.take(maxNodes)
  }
  for (family <- request("allowed_relations").arr.map(_.str).distinct) {
    val out = Arr()
    families(family) = out
    try {
      family match {
        case "call" =>
          emit(out, "anchor", "anchored_call", anchor)
          bounded(anchor.callee).foreach(m => emit(out, "callee_definition", "calls", m))
          var frontier = List(anchor.method)
          val seen = mutable.Set(anchor.method.id)
          for (_ <- 0 until maxDepth if frontier.nonEmpty) {
            val callers = bounded(frontier.iterator.flatMap(_.callIn))
            callers.foreach(c => emit(out, "call_neighbor", "called_by", c))
            frontier = callers.map(_.method).filter(m => seen.add(m.id))
          }
        case "argument" =>
          emit(out, "anchor", "anchored_call", anchor)
          bounded(anchor.argument.filter(a => optional("argument_index").forall(v => a.argumentIndex == v.num.toInt)))
            .foreach(a => emit(out, "argument", "has_argument", a))
          bounded(anchor.callee.parameter.filter(p => optional("argument_index").forall(v => p.index == v.num.toInt)))
            .foreach(p => emit(out, "callee_parameter_use", "binds_parameter", p))
        case "declaration" | "type" =>
          val relevant = bounded(anchor.method.ast.filter(matchesEntity).filter(n =>
            family == "type" || n.isInstanceOf[Local] || n.isInstanceOf[MethodParameterIn]))
          relevant.foreach(n => emit(out, if (family == "type") "type" else "declaration",
            if (family == "type") "has_type" else "declared_in", n))
          if (entity.isEmpty) limitations.value += Obj("kind" -> "entity_required", "detail" -> s"$family: an entity is required")
        case "data_flow" =>
          if (!cpg.metaData.headOption.exists(_.overlays.contains("ossdataflow"))) run.ossdataflow
          val sources = bounded(anchor.method.ast.filter(matchesEntity))
          val sinks: Iterator[CfgNode] = optional("argument_index") match {
            case Some(index) => anchor.argument.filter(_.argumentIndex == index.num.toInt).map(x => x: CfgNode)
            case None => Iterator.single(anchor)
          }
          val paths = sinks.reachableByFlows(sources.iterator).take(maxFlows + 1).toList
          if (paths.size > maxFlows) truncated = true
          paths.take(maxFlows).foreach(p => emit(out, "data_flow_path", "flows_to", anchor, p.elements.toList))
          if (sources.isEmpty) limitations.value += Obj("kind" -> "flow_sources_missing", "detail" -> "data_flow: no matching source entity")
        case "control_dependence" =>
          bounded(Iterator.single(anchor).controlledBy).foreach(n => emit(out, "control_dependence", "controlled_by", n))
          bounded(Iterator.single(anchor).dominatedBy).foreach(n => emit(out, "dominance", "dominated_by", n))
          bounded(Iterator.single(anchor).postDominatedBy).foreach(n => emit(out, "dominance", "post_dominated_by", n))
        case _ => throw new IllegalArgumentException("unsupported family")
      }
    } catch {
      case NonFatal(_) => limitations.value += Obj("kind" -> "query_family_failed", "detail" -> s"$family: graph query failed")
    }
    if (out.value.isEmpty) limitations.value += Obj("kind" -> "query_family_empty", "detail" -> s"$family: no mapped relation was found")
  }
  write("exact", 1)
}
