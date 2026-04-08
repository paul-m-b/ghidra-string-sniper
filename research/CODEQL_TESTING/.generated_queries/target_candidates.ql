/**
 * Resolve source-level candidate functions by unqualified name.
 */
import cpp

from Function f
where
  f.fromSource() and
  f.getName() = "getMessage"
select
  f.getName(),
  f.getQualifiedName(),
  f.getLocation().getFile().getRelativePath(),
  f.getLocation().getStartLine(),
  f.getLocation().getStartColumn(),
  f.getLocation().getEndLine(),
  f.getLocation().getEndColumn()
