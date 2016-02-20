/*
 *  JavaScript Bundler
 *  Copyright (C) 2016  Nikolay Platov
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package nikoladasm.javascript.bundler;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import nikoladasm.javascript.utils.JSUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE;
import static nikoladasm.javascript.utils.JSUtils.*;

public class BandlerService {

	private static final String BANDLE_IIFE_HEADER =
		"(function launcher(moduleMap, cache, mainMod) {\n" +
		"\"use strict\";\n";
	private static final String BANDLE_IIFE_BODY =
		"function req(mNum){\n" +
		"if (mNum in cache) {\n" +
		"return cache[mNum];\n" +
		"} else if (mNum in moduleMap) {\n" +
		"var module = {exports:{}};\n" +
		"cache[mNum] = {};\n" +
		"cache[mNum] = moduleMap[mNum].call(module.exports,\n" +
		"function(n) {return req(n);}, module.exports, module,\n" +
		"launcher, moduleMap, cache, mainMod);\n" +
		"return cache[mNum];\n" +
		"} else throw new Error('Incorrect dependency');\n" +
		"};\n" +
		"req(mainMod);\n";
	private static final String BANDLE_IIFE_FOOTER =
		"})\n";
	private static final String BANDLE_IIFE_PARAMETERS_HEADER =
		"(";
	private static final String BANDLE_IIFE_PARAMETERS_FOOTER =
		");";
	private static final String BANDLE_MAP_HEADER =
		"{\n";
	private static final String BANDLE_MAP_FOOTER =
		"}";
	private static final String BANDLE_MODULES_CACHE =
		"{}";
	private static final String BANDLE_MAP_MODULES_HEADER =
		"function(require, exports, module) {\n";
	private static final String BANDLE_MAP_MODULES_FOOTER =
		"return module.exports;\n}";

	private final Logger LOG;

	private Path topModule;
	private Path rootModule;
	private JSUtils utils = new JSUtils();
	private Set<Path> excludesPaths;
	private Map<Path,Path> es5DependenciesPathsMap = new HashMap<>();;
	private Path basePath;
	private Path tmpPath;
	private List<Path> excludedFromTransformationFiles;
	private List<Path> excludedFromTransformationDirs;
	private Map<Path,Map<String,Path>> cjsDependencies;
	private Path temporyBundlePath;
	private Path output;
	private int period;
	private ScheduledExecutorService service =
		Executors.newSingleThreadScheduledExecutor();
	private StringWriter babelScriptEngineStringWriter;
	private StringWriter uglifyJS2ScriptEngineStringWriter;
	private boolean debug;
	private boolean clearTmpDir;
	private String optimize;
	private String compilation_level;
	
	public BandlerService(Config config) {
		readConfig(config);
		setLoggerProperty();
		LOG = LoggerFactory.getLogger("Bundler");
	}
	
	private void readConfig(Config config) {
		basePath = config.basePath;
		tmpPath = basePath.resolve(config.tmpDir).normalize();
		topModule = basePath.resolve(config.topModule).toAbsolutePath().normalize();
		excludedFromTransformationFiles =
			(config.excludedFromTransformationFiles == null) ?
			new LinkedList<>() : config.excludedFromTransformationFiles;
		excludedFromTransformationDirs =
			(config.excludedFromTransformationDirs == null) ?
			new LinkedList<>()	: config.excludedFromTransformationDirs;
		output = basePath.resolve(config.output).toAbsolutePath().normalize();
		period = config.period;
		debug = config.debug;
		clearTmpDir = config.clearTmpDir;
		optimize = config.optimize;
		compilation_level = config.compilation_level;
	}
	
	private void setLoggerProperty() {
		if (debug) {
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
		} else {
			System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
			System.setProperty("org.slf4j.simpleLogger.showLogName", "false");
		}
		System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
		System.setProperty("org.slf4j.simpleLogger.dateTimeFormat","dd.MM.yyyy HH:mm:ss");
	}
	
	private Path changeJSXtoJSExtension(Path originalPath) {
		String originalPathStr = originalPath.toString();
		return Paths.get(originalPathStr.substring(0, originalPathStr.length()-4)+".js");
	}

	private Set<Path> getExcludedPaths() {
		if (excludesPaths != null) return excludesPaths;
		excludesPaths = new HashSet<>();
		excludedFromTransformationFiles.forEach(path -> 
			excludesPaths.add(basePath.resolve(path).toAbsolutePath().normalize()));
		for (Path dPath : excludedFromTransformationDirs) {
			Path fdPath = basePath.resolve(dPath).toAbsolutePath().normalize();
			if (!Files.exists(fdPath) || !Files.isDirectory(fdPath)) continue;
			try  {
				Files.walk(fdPath)
					.filter(Files::isRegularFile)
					.forEach(path -> excludesPaths.add(path));
			} catch (IOException | NullPointerException e) {
				throw new JavaScriptBandlerException("Can't get "+ dPath, e);
			}
		}
		return excludesPaths;
	}

	private String readFileWithTransformationAndWrite(Path path) throws IOException {
		LOG.debug("Resolve dependencies: {}",path);
		Path rpath = basePath.toAbsolutePath().relativize(path);
		Path tPath = tmpPath.resolve(rpath).toAbsolutePath().normalize();
		String es5JSFile;
		if (!getExcludedPaths().contains(path)) {
			LOG.debug("Transformation: {}",path);
			if (path.toString().endsWith(JSX_FILE_EXTENSION)) {
				tPath = changeJSXtoJSExtension(tPath);
				String jsxFile = readFile(path, UTF_8);
				es5JSFile = utils.transformJSXAndES2015toES5(jsxFile);
			} else {
				String es2015File = readFile(path, UTF_8);
				es5JSFile = utils.transformES2015toES5(es2015File);
			}
			if (!Files.exists(tPath)) Files.createDirectories(tPath);
			Files.deleteIfExists(tPath);
			writeFile(es5JSFile, tPath, UTF_8);
		} else {
			LOG.debug("Coping: {}",path);
			if (!Files.exists(tPath)) Files.createDirectories(tPath);
			Files.deleteIfExists(tPath);
			Files.copy(path, tPath, REPLACE_EXISTING);
			es5JSFile = readFile(path, UTF_8);
		}
		if (path.equals(rootModule)) rootModule = tPath;
		es5DependenciesPathsMap.put(path, tPath);
		return es5JSFile;
	}
	
	private void processCJSDependencies() {
		rootModule = topModule;
		utils.setCJSResolverFileReader(this::readFileWithTransformationAndWrite);
		babelScriptEngineStringWriter = new StringWriter();
		utils.babelScriptEngineStringWriter(babelScriptEngineStringWriter);
		Map<Path,Map<String,Path>> srcCJSDependencies = utils.getCJSDependenciesMap(rootModule);
		String capturedOutput = babelScriptEngineStringWriter.toString();
		if (!capturedOutput.trim().isEmpty()) LOG.debug(capturedOutput);
		cjsDependencies = new HashMap<>();
		srcCJSDependencies.forEach((path, requirePathMap) -> {
			Map<String,Path> requireArgPathMap = new HashMap<>();
			requirePathMap.forEach((requireArg, fPath) ->
				requireArgPathMap.put(requireArg, es5DependenciesPathsMap.get(fPath)));
			cjsDependencies.put(es5DependenciesPathsMap.get(path), requireArgPathMap);
		});
	}
	
	private void buildBandle() {
		temporyBundlePath = tmpPath.resolve(UUID.randomUUID().toString()+".bandle.tmp").toAbsolutePath().normalize();
		Map<Path,Integer> moduleMap = new HashMap<>();
		int i = 1;
		for (Path path: cjsDependencies.keySet()) {
			moduleMap.put(path, i);
			i++;
		}
		try {
			if (!Files.exists(temporyBundlePath)) Files.createDirectories(temporyBundlePath);
			Files.deleteIfExists(temporyBundlePath);
			try (BufferedWriter bwr = new BufferedWriter(
					new OutputStreamWriter(
						Files.newOutputStream(temporyBundlePath, CREATE), UTF_8))) {
				bwr.write(BANDLE_IIFE_HEADER);
				bwr.write(BANDLE_IIFE_BODY);
				bwr.write(BANDLE_IIFE_FOOTER);
				bwr.write(BANDLE_IIFE_PARAMETERS_HEADER);
				bwr.write(BANDLE_MAP_HEADER);
				int j=1;
				for (Path path: moduleMap.keySet()) {
					LOG.debug("Add to bundle: {}",path);
					bwr.write(moduleMap.get(path)+": "+ BANDLE_MAP_MODULES_HEADER);
					String source = readFile(path, UTF_8);
					for (Entry<String,Path> entry : cjsDependencies.get(path).entrySet()) {
						String fArg = entry.getKey();
						Path fPath = entry.getValue();
						source = source.replaceAll("(require\\s*\\(\\s*)['\"]"+Pattern.quote(fArg)+"['\"](\\s*\\))", "$1"+moduleMap.get(fPath).toString()+"$2");
					}
					bwr.write(source);
					bwr.write(BANDLE_MAP_MODULES_FOOTER+((j < moduleMap.size()) ? ",\n" : "\n"));
					j++;
				}
				bwr.write(BANDLE_MAP_FOOTER);
				bwr.write(","+BANDLE_MODULES_CACHE);
				bwr.write(","+moduleMap.get(rootModule.toAbsolutePath()));
				bwr.write(BANDLE_IIFE_PARAMETERS_FOOTER);
			}
		} catch (IOException e) {
			throw new JavaScriptBandlerException("Can't create bundle", e);
		}
	}
	
	private void optimizeBundle() {	
		try {
			if (!Files.exists(output.getParent())) Files.createDirectories(output.getParent());
			switch(optimize.toLowerCase()) {
				case "none" : {
					Files.copy(temporyBundlePath, output, REPLACE_EXISTING);
					break;
				}
				case "closure" : {
					List<String> arguments = new LinkedList<>();
					arguments.add("--language_in");
					arguments.add("ECMASCRIPT5_STRICT");
					arguments.add("--language_out");
					arguments.add("ECMASCRIPT5_STRICT");
					arguments.add("--compilation_level");
					arguments.add(compilation_level);
					arguments.add("--js");
					arguments.add(temporyBundlePath.toString());
					arguments.add("--js_output_file");
					arguments.add(output.toString());
					utils.runClousureCompilerOptimizer(arguments.toArray(new String[arguments.size()]));
					break;
				}
				default : {
					uglifyJS2ScriptEngineStringWriter = new StringWriter();
					utils.uglifyJS2ScriptEngineStringWriter(uglifyJS2ScriptEngineStringWriter);
					String minified = utils.optimizeByUglifyJS2Script(readFile(temporyBundlePath, UTF_8), null);
					Files.deleteIfExists(output);
					writeFile(minified, output, UTF_8);
					String capturedOutput = uglifyJS2ScriptEngineStringWriter.toString();
					if (!capturedOutput.trim().isEmpty()) LOG.debug(capturedOutput);
					break;
				}
			}
		} catch (IOException e) {
			throw new JavaScriptBandlerException("Can't optimize bundle", e);
		}
	}
	
	private void clearDir(Path path) {
		try {
			if (Files.exists(path) && Files.isDirectory(path)) { 
				Files.walk(path)
					.filter(Files::isRegularFile)
					.map(Path::toFile)
					.forEach(f -> f.delete());
				Files.walk(path)
					.filter(Files::isDirectory)
					.filter(p -> !p.equals(path))
					.forEach(this::clearDir);
			}
			Files.deleteIfExists(path);
		} catch (IOException e) {}
	}
	
	public void bandle() {
		try{
			LOG.info("Creating bandle...");
			LOG.info("Resolving dependencies");
			processCJSDependencies();
			LOG.info("Building bandle");
			buildBandle();
			LOG.info("Optimizing bandle");
			optimizeBundle();
			if (clearTmpDir) {
				LOG.info("Clearing temp directory");
				clearDir(tmpPath);
			}
			LOG.info("Bandle successfully created");
		} catch (Exception e) {
			if (debug)
				LOG.error("Bandle did't create.", e);
			else
				LOG.error("Bandle did't create.");
		}
	}
	
	public void runPeriodicBandleBuilder() {
		service.scheduleWithFixedDelay(() -> {
			bandle();
		}, 0, period, TimeUnit.SECONDS);
	}
	
	public void stopPeriodicBandleBuilder() {
		if (clearTmpDir) {
			LOG.info("Clearing temp directory");
			clearDir(tmpPath);
		}
		LOG.info("Service stopping...");
		service.shutdown();
		try {
			if (!service.awaitTermination(120, TimeUnit.SECONDS)) {
				LOG.error("Can't stop service");
			}
		} catch (InterruptedException e) {
			service.shutdownNow();
		}
	}
}
