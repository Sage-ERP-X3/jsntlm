"use strict";
var babel = require('babel-core');
var fs = require('fs');
var fsp = require('path');

var dirMode = parseInt('777', 8);

function mkdirs(dir) {
	if (fs.existsSync(dir)) return;
	mkdirs(fsp.join(dir, '..'));
	fs.mkdirSync(dir, dirMode);
}

function transform(src, dir, dst, map) {
	var babelOptions = {
		filename: src,
		sourceFileName: src,
		sourceMaps: true,
	};
	var source = fs.readFileSync(src, 'utf8');
	var transformed =  babel.transform(source, babelOptions);
	var code = transformed.code + '\n//# sourceMappingURL=' + map;
	console.error("creating", fsp.join(dir, dst));
	fs.writeFileSync(fsp.join(dir, dst), code, 'utf8');
	fs.writeFileSync(fsp.join(dir, map), JSON.stringify(transformed.map, null, '\t'), 'utf8');
}

function build(src, dst) {
	fs.readdirSync(src).forEach(function(name) {
		var path = fsp.join(src, name);
		var stat = fs.statSync(path);
		mkdirs(dst);
		if (stat.isDirectory()) {
			var sub = fsp.join(dst, name);
			build(path, sub);
		} else if (/\._?js$/.test(name)) {
			transform(path, 
				dst,
				name, 
				name.replace(/\.js$/, '.map'));			
		}
	});
}

build(fsp.join(__dirname, 'src'), fsp.join(__dirname, 'lib'));
