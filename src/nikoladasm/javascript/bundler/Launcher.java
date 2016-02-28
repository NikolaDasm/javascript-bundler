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

import java.io.Console;

import nikoladasm.commons.configuration.properties.PropertyLoader;

public class Launcher {
	
	public static void main(String[] args) {
		Config config = PropertyLoader.getInstance().populate(Config.class);
		BandlerService service = new BandlerService(config);
		if (args.length == 1) {
			switch(args[0].toLowerCase()) {
				case "-service" :
				case "-s" : {
					service.runPeriodicBandleBuilder();
					System.out.println("Bandler service run");
					Console console = System.console();
					System.out.println("Enter \"x\" for exit");
					try {
						while (!console.readLine().trim().equalsIgnoreCase("x"));
					} catch (Exception e) {}
					service.stopPeriodicBandleBuilder();
					break;
				}
				case "-bundle" :
				case "-b" :
				default : {
					service.bandle();
					break;
				}
			}
		} else {
			service.bandle();
		}
	}
}
