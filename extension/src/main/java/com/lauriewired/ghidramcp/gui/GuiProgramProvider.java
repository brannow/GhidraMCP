package com.lauriewired.ghidramcp.gui;

import java.lang.reflect.InvocationTargetException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import java.util.ArrayList;
import java.util.List;
import com.lauriewired.ghidramcp.core.McpException;
import com.lauriewired.ghidramcp.core.Model;
import com.lauriewired.ghidramcp.core.ProgramProvider;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Targets the program that is active in the Ghidra tool. Writes run on the Swing thread.
 */
public class GuiProgramProvider implements ProgramProvider {

	private final PluginTool tool;

	public GuiProgramProvider(PluginTool tool) {
		this.tool = tool;
	}

	@Override
	public Program getProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm != null ? pm.getCurrentProgram() : null;
	}

	@Override
	public String mode() {
		return "gui";
	}

	@Override
	public Set<String> capabilities() {
		return Set.of(CAP_GUI_CONTEXT);
	}

	@Override
	public Address getCurrentAddress() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null) {
			throw McpException.unsupported("Code viewer service not available");
		}
		ProgramLocation location = service.getCurrentLocation();
		if (location == null || location.getAddress() == null) {
			throw McpException.notFound("No current location in the listing");
		}
		return location.getAddress();
	}

	@Override
	public DataTypeQueryService getDataTypeService() {
		return tool.getService(DataTypeManagerService.class);
	}

	@Override
	public <T> T runWrite(Supplier<T> action) {
		if (SwingUtilities.isEventDispatchThread()) {
			return action.get();
		}
		AtomicReference<T> result = new AtomicReference<>();
		AtomicReference<RuntimeException> failure = new AtomicReference<>();
		try {
			SwingUtilities.invokeAndWait(() -> {
				try {
					result.set(action.get());
				}
				catch (RuntimeException e) {
					failure.set(e);
				}
			});
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw McpException.failed("Interrupted while waiting for the Swing thread", e);
		}
		catch (InvocationTargetException e) {
			throw McpException.failed("Write failed on the Swing thread: " + e.getCause(), e);
		}
		if (failure.get() != null) {
			throw failure.get();
		}
		return result.get();
	}

	// ------------------------------------------------------------------------------------------
	// hd2-extensions: program control
	// ------------------------------------------------------------------------------------------

	private ProgramManager programManager() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			throw McpException.unsupported("Program manager service not available");
		}
		return pm;
	}

	@Override
	public Model.GoTo goTo(Address address) {
		GoToService goTo = tool.getService(GoToService.class);
		if (goTo == null) {
			throw McpException.unsupported("Go-to service not available");
		}
		boolean moved = runWrite(() -> goTo.goTo(address));
		return new Model.GoTo(address.toString(), moved);
	}

	@Override
	public List<Model.OpenProgram> listOpenPrograms() {
		return runWrite(() -> {
			ProgramManager pm = programManager();
			Program current = pm.getCurrentProgram();
			List<Model.OpenProgram> out = new ArrayList<>();
			for (Program p : pm.getAllOpenPrograms()) {
				out.add(new Model.OpenProgram(p.getName(), p.getDomainFile().getPathname(), p == current));
			}
			return out;
		});
	}

	/** Make a program the current tab, opening it from the project first if needed. */
	@Override
	public Model.OpenProgram openProgram(String name) {
		if (name == null || name.isBlank()) {
			throw McpException.missingParameter("name");
		}
		return runWrite(() -> {
			ProgramManager pm = programManager();
			for (Program p : pm.getAllOpenPrograms()) {
				if (p.getName().equalsIgnoreCase(name) ||
					p.getDomainFile().getPathname().equalsIgnoreCase(name)) {
					pm.setCurrentProgram(p);
					return new Model.OpenProgram(p.getName(), p.getDomainFile().getPathname(), true);
				}
			}
			Project project = tool.getProject();
			DomainFile file = project == null ? null :
				findFile(project.getProjectData().getRootFolder(), name);
			if (file == null) {
				throw McpException.notFound("No program named '" + name + "' in the project");
			}
			Program p = pm.openProgram(file);
			if (p == null) {
				throw McpException.failed("Could not open " + file.getPathname());
			}
			pm.setCurrentProgram(p);
			return new Model.OpenProgram(p.getName(), file.getPathname(), true);
		});
	}

	private static DomainFile findFile(DomainFolder folder, String name) {
		for (DomainFile f : folder.getFiles()) {
			if (f.getName().equalsIgnoreCase(name) || f.getPathname().equalsIgnoreCase(name)) {
				return f;
			}
		}
		for (DomainFolder sub : folder.getFolders()) {
			DomainFile f = findFile(sub, name);
			if (f != null) {
				return f;
			}
		}
		return null;
	}
}
