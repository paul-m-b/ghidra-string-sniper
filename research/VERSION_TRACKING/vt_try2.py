# @runtime Jython

from ghidra.feature.vt.api.correlator.program import ExactDataMatchProgramCorrelatorFactory
from ghidra.feature.vt.api.correlator.program import ExactMatchBytesProgramCorrelatorFactory
from ghidra.feature.vt.api.correlator.program import ExactMatchInstructionsProgramCorrelatorFactory
from ghidra.feature.vt.api.db import VTSessionDB, VTSessionContentHandler
from ghidra.program.model.listing import Program


def fail(msg):
    printerr(msg)
    raise Exception(msg)


def split_project_path(project_path):
    """
    '/foo/bar/baz' -> ('/foo/bar', 'baz')
    '/baz'         -> ('/', 'baz')
    'baz'          -> ('/', 'baz')
    """
    p = project_path.strip()
    if not p:
        fail("Empty project path for source program")

    if not p.startswith("/"):
        p = "/" + p

    if p == "/":
        fail("Source program path must include a filename")

    idx = p.rfind("/")
    folder = p[:idx]
    name = p[idx + 1:]

    if folder == "":
        folder = "/"

    return folder, name


def get_folder_by_path(project_data, folder_path):
    folder = project_data.getRootFolder()

    if folder_path == "" or folder_path == "/":
        return folder

    parts = folder_path.split("/")
    for part in parts:
        if not part:
            continue
        folder = folder.getFolder(part)
        if folder is None:
            fail("Project folder does not exist: " + folder_path)

    return folder


def open_program_from_project(project_path):
    project = state.getProject()
    if project is None:
        fail("No active Ghidra project")

    project_data = project.getProjectData()
    folder_path, filename = split_project_path(project_path)
    folder = get_folder_by_path(project_data, folder_path)
    df = folder.getFile(filename)

    if df is None:
        fail("Project file not found: " + project_path)

    if not Program.class_.isAssignableFrom(df.getDomainObjectClass()):
        fail("Project file is not a Program: " + project_path)

    auto_upgrade_if_needed = isRunningHeadless()
    return df.getDomainObject(self, auto_upgrade_if_needed, False, monitor)


def ensure_session_folder(project_folder_path):
    project = state.getProject()
    if project is None:
        fail("No active Ghidra project")

    project_data = project.getProjectData()
    folder = project_data.getRootFolder()

    if project_folder_path == "" or project_folder_path == "/":
        return folder

    parts = project_folder_path.split("/")
    for part in parts:
        if not part:
            continue
        next_folder = folder.getFolder(part)
        if next_folder is None:
            next_folder = folder.createFolder(part)
        folder = next_folder

    return folder


def has_existing_session(folder, session_name):
    df = folder.getFile(session_name)
    if df is None:
        return False
    return df.getContentType() == VTSessionContentHandler.CONTENT_TYPE


def run_correlator(session, source_program, dest_program, factory):
    source_set = source_program.getMemory().getLoadedAndInitializedAddressSet()
    dest_set = dest_program.getMemory().getLoadedAndInitializedAddressSet()
    options = factory.createDefaultOptions()
    correlator = factory.createCorrelator(
        source_program,
        source_set,
        dest_program,
        dest_set,
        options
    )
    return correlator.correlate(session, monitor)


def summarize_session(session):
    total_match_sets = 0
    total_matches = 0

    for match_set in session.getMatchSets():
        total_match_sets += 1
        count = match_set.getMatchCount()
        total_matches += count
        println("  - " + str(match_set) + ": " + str(count) + " matches")

    println("VT summary: " + str(total_match_sets) + " match set(s), " +
            str(total_matches) + " total match(es)")

def main():
    if currentProgram is None:
        fail("This script must be run with the destination program as currentProgram")

    args = getScriptArgs()
    if len(args) != 3:
        fail("Usage: <source_project_path> <session_name> <session_folder>")

    source_project_path = args[0]
    session_name = args[1]
    session_folder_path = args[2]

    dest_program = currentProgram
    if not dest_program.canSave():
        fail("Destination program is read-only: " + dest_program.getName())

    source_program = None
    session = None

    try:
        source_program = open_program_from_project(source_project_path)
        folder = ensure_session_folder(session_folder_path)

        if has_existing_session(folder, session_name):
            fail("VT session already exists: " + session_folder_path + "/" + session_name)

        # Follow Ghidra's example pattern: close out the script transaction before VT work.
        end(True)

        session = VTSessionDB(session_name, source_program, dest_program, self)
        folder.createFile(session_name, session, monitor)

        tx = session.startTransaction("Headless VT exact correlators")
        committed = False

        try:
            factories = [
                ExactDataMatchProgramCorrelatorFactory(),
                ExactMatchBytesProgramCorrelatorFactory(),
                ExactMatchInstructionsProgramCorrelatorFactory()
            ]

            for factory in factories:
                println("Running correlator: " + factory.getName())
                result_set = run_correlator(session, source_program, dest_program, factory)
                println("  -> " + str(result_set.getMatchCount()) + " matches")

            session.endTransaction(tx, True)
            committed = True
        finally:
            if not committed:
                try:
                    session.endTransaction(tx, False)
                except:
                    pass

        dest_program.save("Updated by headless VT script", monitor)
        session.save("Saved headless VT session", monitor)

        summarize_session(session)
        println("Created VT session '" + session_name + "' in '" + session_folder_path + "'")

    finally:
        if source_program is not None:
            source_program.release(self)
        if session is not None:
            session.release(self)


main()
