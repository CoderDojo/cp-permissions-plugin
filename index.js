'use strict';

var _ = require('lodash');
var async = require('async');
var crypto = require('crypto');

module.exports = function (options) {
  var seneca = this;
  var plugin = 'cd-core';

  seneca.add({role: 'cd-core', cmd: 'check_permissions'},
    require('./lib/check_permissions').bind( _.extend(_.clone(this), {permConfig: options.config}) ));

  seneca.wrap({role: options.target}, function(msg, respond){
    if(!msg.meta$.token && !msg.meta$.hash || !verifyToken(msg.meta$.token, msg.meta$.hash)){
      seneca.act({role: 'cd-core', cmd: 'check_permissions', msg: msg},
        (function (err, response){
          if(response && !_.isObject(response)){
            msg.meta$.token = Date.now().toString();
            msg.meta$.hash = createToken(msg.meta$.token);
            this.prior(msg, respond);
          } else {
            respond(null, {http$: response});
          }
        }).bind(this)
      );
    } else {
      this.prior(msg, respond);
    }
  });

  var verifyToken =  function (token, hash) {
    var valid = false;
    if (createToken(token) === hash){
        valid = true;
    }
    return valid;
  };

  var createToken = function (token) {
    var hash = crypto.createHmac('sha512', process.env.PERM_MASTERKEY);
    hash.update(token);
    return hash.digest('hex');
  };


  return {
    name: plugin
  };
};