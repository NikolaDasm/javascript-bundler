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

import static nikoladasm.commons.configuration.properties.annotations.Resource.Type.FILE;

import java.nio.file.Path;
import java.util.List;

import nikoladasm.commons.configuration.properties.annotations.*;

@Resource(source=FILE, value="config.properties")
public class Config {
	
	@Property("base.path")
	@DefaultValue("webapp")
	public Path basePath;
	
	@Property("tmp.dir")
	@DefaultValue("../tmp")
	public Path tmpDir;
	
	@Property("top.module")
	public Path topModule;
	
	@Property("transformation.exclude.files")
	public List<Path> excludedFromTransformationFiles;
	
	@Property("transformation.exclude.dirs")
	public List<Path> excludedFromTransformationDirs;
	
	@Property("output")
	public Path output;
	
	@Property("delay")
	@DefaultValue("5")
	public int delay;
	
	@Property("debug")
	@DefaultValue("false")
	public boolean debug;
	
	@Property("clear.tmp.dir")
	@DefaultValue("true")
	public boolean clearTmpDir;
	
	@Property("optimize")
	@DefaultValue("uglify2")
	public String optimize;
	
	@Property("closure.compilation_level")
	@DefaultValue("SIMPLE")
	public String compilation_level;
	
	@Property("transformation.only.changed")
	@DefaultValue("true")
	public boolean transformationOnlyChanged;
	
	@Property("hot.reload")
	@DefaultValue("false")
	public boolean hotReload;

	@Property("server.ipaddress")
	@DefaultValue("0.0.0.0")
	public String ipAddress;
	
	@Property("server.port")
	@DefaultValue("8080")
	public int port;
	
	@Property("server.static.file.location")
	@DefaultValue("resources/public")
	public String staticFileLocation;
}
