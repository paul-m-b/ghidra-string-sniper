/**
 * Find outgoing call references from one exact source function.
 */
import cpp

predicate isTarget(Function f) {
  f.getLocation().getFile().getRelativePath() = "server.c" and
  f.getLocation().getStartLine() = 39 and
  f.getLocation().getStartColumn() = 7
}
from FunctionCall call
where
  isTarget(call.getEnclosingFunction()) and
  exists(call.getTarget())
select
  call.getEnclosingFunction().getName(),
  call.getEnclosingFunction().getQualifiedName(),
  call.getEnclosingFunction().getLocation().getFile().getRelativePath(),
  call.getEnclosingFunction().getLocation().getStartLine(),
  call.getEnclosingFunction().getLocation().getStartColumn(),
  call.getEnclosingFunction().getLocation().getEndLine(),
  call.getEnclosingFunction().getLocation().getEndColumn(),
  call.getTarget().getName(),
  call.getTarget().getQualifiedName(),
  "",
  0,
  0,
  0,
  0,
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getStartColumn(),
  call.getLocation().getEndLine(),
  call.getLocation().getEndColumn()
