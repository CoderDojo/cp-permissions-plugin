var async = require('async');
var _ = require('lodash');
var checkProfiles = require('./check_profiles');

/**
 * [checkPermissions description]
 * Format of a permission {
 * role: 'basic-user'
 * userType: 'parent-guardian'
 * customValidator: [{
 *  role: 'cd-x',
 *  cmd: 'fn'
 * }]
 *}
 *
 * @param  {[type]}   args [description]
 * @param  {Function} done [description]
 * @return {[type]}        [description]
 */

function checkPermissions (args, cb) {
  var seneca = this;
  var cmd = args.act;
  var ctrl = args.params && args.params.ctrl;
  seneca.log.debug('tested:', args.role, cmd);
  var origin = args.role;
  var rules = seneca.export('cd-permissions/config')[origin];

  function getProfilesByActName (waterfallCb) {
    var profiles = {};
    // TODO : refactor to avoid having to add subpatterns conditionnally
    // https://github.com/CoderDojo/cp-permissions-plugin/issues/8
    if (rules[cmd]) profiles = rules[cmd];
    if (rules[ctrl] && rules[ctrl][cmd]) profiles = rules[ctrl][cmd];
    waterfallCb(null, profiles, args);
  }

  async.waterfall([
    getProfilesByActName,
    checkProfiles.bind(this)
  ], cb);
}

module.exports = checkPermissions;
