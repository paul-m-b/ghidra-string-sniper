/**
 * Find incoming call references to one exact source function.
 */
import cpp

predicate isTarget(Function f) {
  f.fromSource() and
  f.getLocation().getFile().getRelativePath() = "server.c" and
  f.getLocation().getStartLine() = 39 and
  f.getLocation().getStartColumn() = 7
}

from Function target, Function caller, FunctionCall call
where
  isTarget(target) and
  call.getTarget() = target and
  caller = call.getEnclosingFunction()
select
  target.getName(),
  target.getQualifiedName(),
  target.getLocation().getFile().getRelativePath(),
  target.getLocation().getStartLine(),
  target.getLocation().getStartColumn(),
  target.getLocation().getEndLine(),
  target.getLocation().getEndColumn(),
  caller.getName(),
  caller.getQualifiedName(),
  caller.getLocation().getFile().getRelativePath(),
  caller.getLocation().getStartLine(),
  caller.getLocation().getStartColumn(),
  caller.getLocation().getEndLine(),
  caller.getLocation().getEndColumn(),
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(),
  call.getLocation().getStartColumn(),
  call.getLocation().getEndLine(),
  call.getLocation().getEndColumn()
