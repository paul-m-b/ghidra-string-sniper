# Ghidra script to automate Version Tracking analysis

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Program
from ghidra.feature.vt.api.main import VTSession, VTMatch
from ghidra.feature.vt.api.correlator import VTRunCorrelationTask
from ghidra.feature.vt.api.util import VTAssociationType
from ghidra.util.task import ConsoleTaskMonitor

class VersionTrackingScript(GhidraScript):
    def run(self):
        with open("/tmp/ghidra_script.log", "w") as f:
            f.write("Script started\n")

        self.log.info("Version Tracking Script Started")
        # This script requires two programs to be open.
        source_program = None
        destination_program = None

        project = self.state.getProject()
        self.log.info("Project: " + str(project))
        root_folder = project.getProjectData().getRootFolder()
        self.log.info("Root Folder: " + str(root_folder))

        for file in root_folder.getFiles():
            self.log.info("Found file: " + str(file.getName()))
            if "source" in file.getName().lower():
                source_program = self.getProgram(file)
                self.log.info("Found source program: " + str(source_program.getName()))
            elif "destination" in file.getName().lower():
                destination_program = self.getProgram(file)
                self.log.info("Found destination program: " + str(destination_program.getName()))
        
        if source_program is None or destination_program is None:
            self.log.error("Could not find source and destination programs.")
            return

        # Create a new version tracking session
        session = VTSession.create(source_program, destination_program, self)
        self.log.info("Version tracking session created.")
        
        # Get all available correlators
        correlators = session.getAvailableCorrelators()
        self.log.info("Available correlators: " + str(correlators))

        # Create a task to run the correlators
        task = VTRunCorrelationTask(session, correlators)
        
        # Run the task with a monitor
        monitor = ConsoleTaskMonitor()
        task.run(monitor)
        self.log.info("Correlation task complete.")

        # Save the session
        session.save()

        self.log.info("Version tracking analysis complete.")

    def getProgram(self, domainFile):
        # Helper function to get a program object from a domain file
        monitor = ConsoleTaskMonitor()
        return domainFile.getDomainObject(self, False, False, monitor)


# Create an instance of the script and run it
script = VersionTrackingScript()
script.run()
