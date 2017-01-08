'use strict';
var seneca = require('seneca')();
var checkPerm = require('../lib/check_permissions');
var conf = require('./permissions-rules')();
var _lab = require('lab');
var _ = require('lodash');
var spy = require('sinon').spy;
var lab = exports.lab = _lab.script();
var describe = lab.describe;
var it = lab.it;
var utils = require('./utils');
var isValidFormat = utils.isValidFormat;
var expect = require('code').expect;

process.setMaxListeners(0);


describe('cp-perms', function () {
  var actForAdult = {role: 'cp-test', cmd: 'acting_as_adult'};
  var expectedResult = {'acting': 'as_normal'};

  seneca.add({role: 'cp-test', cmd: 'check_permissions' }, checkPerm.bind( _.extend(_.clone(seneca), conf['cp-test']) ));
  seneca.add({role: 'cp-test', cmd: 'customVal'}, function (args, done) {
    var toTest = args.toTest;
    return done(null, {'allowed': toTest === 'imabanana'? true: false});
  });

  it('should be testing all profiles', function (done) {
    // TODO : refact checkPerm to expose isUserTypeAllowed
    var leSpy = spy(checkPerm, 'isUserTypeAllowed');
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: ['parent']}}, function (err, allowance) {
      expect(spy.callCount).to.be.deep.equal(conf['cp-test'][actForAdult.cmd]);
      done();
    });
  });
  
  it('should be testing all profiles until one is valid')
};
