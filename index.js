'use strict';

var _ = require('lodash');
var async = require('async');

module.exports = function (options) {
  var seneca = this;
  var plugin = 'cd-permissions';

  //  Required params
  var config = require(options.config)();

  var addValidator = function (lib) {
    seneca.add({role: lib, cmd: 'check_permissions'},
      require('./lib/check_permissions'));
  };

  _.each(_.keys(config), addValidator);

  return {
    name: plugin,
    exportmap: {
      config: config
    }
  };
};
