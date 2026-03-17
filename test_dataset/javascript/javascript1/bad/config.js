// Vulnerable to dynamic code inclusion
const plugin = require("./plugins/" + req.body.pluginName);
plugin.init();
