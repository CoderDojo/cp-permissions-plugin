var async = require('async');
var _ = require('lodash');

/**
 * [checkProfiles description]
 * Format of a permission {
 * role: 'basic-user'
 * userType: 'parent-guardian'
 * customValidator: [{
 *  role: 'cd-x',
 *  cmd: 'fn'
 * }]
 *}
 *
 * @param  {[type]}   profiles [description]
 * @param  {[type]}   args     [description]
 * @param  {Function} cb       [description]
 * @return {[type]}            [description]
 */

function checkProfiles (profiles, args, cb) {
  var seneca = this;
  var permissions = require('../config/permissions.js')();
  var httpErr = {};
  var extendedUserTypes = [];
  var maxUserTypeDepth = 6; // TODO: this should be calculated
  var maxUserRoleDepth = 4; // TODO: this should be calculated
  var user = args.user ? args.user : {roles: ['none']};

  /**
   * Check different parameters based upon a profile rule to ensure the actual user is allowed to use it
   * The validity is global to every check, while the error is passed as callback of every check
   * @param  {Object} profile    Instance of an act profile containing minimal status to use this act
   */
  function checkValidity (profile, validityCb) {
    var actions = [];
    var allowed = true; // This is a local validity to each rule/profile

    if (profile.role) actions.push(isRoleAllowed);
    if (profile.extendedUserTypes) actions.push(getAssociatedUserTypes);
    if (profile.userType) actions.push(isUserTypeAllowed);
    if (profile.customValidator) actions.push(applyCustomValidator);

    async.waterfall(actions, function (err, validities) {
      // We can't return err as httpErr because if one of the profiles fails, it stops the other possible profiles tests
      return validityCb(null, allowed);
    });

    /**
     * Check if the profile role is matching (or lower) than the caller
     * @return {Object}      [description]
     */
    function isRoleAllowed (done) {
      httpErr = {
        status: 403
      };
      var profileDepth = getTreeDepth(permissions.roleHierarchy, profile.role, maxUserRoleDepth);
      if (!_.isArray(user.roles) && _.isString(user.roles)) user.roles = [user.roles];
      var userRoleDepth = getHighestTreeMatch(permissions.roleHierarchy, user.roles, maxUserRoleDepth);
      if (profileDepth >= userRoleDepth.value && userRoleDepth.value < maxUserRoleDepth) {
        allowed = allowed && true;
        httpErr = null;
      } else {
        allowed = false;
      }
      //  Out of jail scenario for highest role
      //  We bypass further check to avoid over defining scenarios
      if (userRoleDepth.value === 0) {
        return validityCb(null, true);
      }
      return done(httpErr);
    }

    function isUserTypeAllowed (done) {
      httpErr = {
        status: 403
      };
      var profileDepth = getTreeDepth(permissions.userTypeHierarchy, profile.userType, maxUserTypeDepth);
      var userTypes = profile.extendedUserTypes ? extendedUserTypes : user.initUserType;

      if (!_.isEmpty(userTypes)) {
        if (!_.isError(_.attempt(JSON.parse, userTypes))) { //
          var initType = JSON.parse(userTypes);
          if (initType.name) {
            userTypes = [initType.name];
          }
        } else if (_.isObject(userTypes) && !_.isArray(userTypes)) {
          userTypes = _.keys(userTypes);
        } else if (_.isString(userTypes)) {
          userTypes = [userTypes];
        }
        var userTypeDepth = getHighestTreeMatch(permissions.userTypeHierarchy, _.toArray(userTypes), maxUserTypeDepth);
        if (profileDepth >= userTypeDepth.value && userTypeDepth.value < maxUserTypeDepth) {
          allowed = allowed && true;
          httpErr = null;
        } else {
          allowed = false;
        }
      } else {
        allowed = false;
      }
      return done(httpErr);
    }

    function getAssociatedUserTypes (done) {
      seneca.act({role: 'cd-dojos', cmd: 'load_usersdojos', query: { userId: user.id }},
        function (err, associations) {
          var userTypes = [];
          userTypes.push(JSON.parse(user.initUserType).name);
          _.map(associations, function (association) {
            _.map(association.userTypes, function (userType) {
              userTypes.push(userType);
            });
          });
          extendedUserTypes = _.uniq(userTypes);
          return done(err);
        });
    }

    /**
     * Call a seneca act based upon the msg saved as a config
     * Params are provided by the original call
     * ex : {role: 'cd-dojos', cmd: 'isDojoAdmin'}
     */
    function applyCustomValidator (done) {
      var customValidator = profile.customValidator;
      httpErr = {
        status: 401
      };
      var omittedFields = [ 'cmd', 'role', 'ungate$', 'transport$', 'tx$', 'default$', 'meta$', 'plugin$', 'fatal$' ];
      // We omit perm on purpose
      async.every(customValidator, function (validatorAct, validatorCb) {
        var msg = _.assign(_.omit(_.clone(args), omittedFields), validatorAct);
        seneca.act(msg, function (err, response) {
          return validatorCb(null, response.allowed);
        });
      }, function (err, valid) {
        if (valid) {
          allowed = valid && true;
          httpErr = null;
        } else {
          allowed = false;
        }
        return done(httpErr);
      });
    }
  }

  /**
   * Flatten a tree of roles to find the value until a maxDepth
   *  As much as possible, avoid recursivness with Js
   * @param  {Object} tree   one of permissions' userTypeHierarchy or roleHierarchy
   * @param  {String} value  one of those tree values
   * @return {Integer}       the depth
   */
  function getTreeDepth (tree, value, maxDepth) {
    var found = false;
    var depth = -1;
    var localTree = _.clone(tree);
    while (!found && depth < maxDepth) {
      var picked = localTree[value];
      depth += 1;
      if (!_.isUndefined(picked)) {
        found = true;
      }
      //  Flatten our object (lodash doesn't support flattening of object, only arrays)
      var tempTree = {};
      _.each(_.keys(localTree), function (key) {
        _.merge(tempTree, localTree[key]);
      });
      localTree = tempTree;
    }
    return depth;
  }

  /**
   * Search for the highest possible value in a tree when multiple options are possible
   * (ex multiple userTypes)
   * @param  {Object} tree   from permissions.js, userTypeHierarchy or roleHierarchy
   * @param  {Array} values  haystack for the highest one
   * @return {String}        one of the userType/Role without the actual index
   */
  function getHighestTreeMatch (tree, values, maxDepth) {
    var lowerDepth = values[0];
    var indexes = {};
    lowerDepth = _.minBy(values, function (value) {
      indexes[value] = getTreeDepth(tree, value, maxDepth);
      return indexes[value];
    });
    return {name: lowerDepth,
      value: indexes[lowerDepth]};
  }

  if (_.isEmpty(profiles)) {
    //  Not define = public call
    seneca.log.debug('No rule defined for this call');
    cb(null, {'allowed': true});
  } else {
    async.someSeries(profiles, checkValidity, function (err, valid) {
      seneca.log.debug('validity', valid === true || httpErr, httpErr);
      cb(null, {'allowed': valid === true || httpErr});
    });
  }
}

module.exports = checkProfiles;
