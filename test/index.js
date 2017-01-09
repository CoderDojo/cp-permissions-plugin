'use strict';
var seneca = require('seneca')();
seneca.use(require('..'), {
  config: __dirname + '/permissions-rules'});
var _lab = require('lab');
var _ = require('lodash');
var async = require('async');
var spy = require('sinon').spy;
var conf = require('./permissions-rules')();
var lab = exports.lab = _lab.script();
var describe = lab.describe;
var it = lab.it;
var utils = require('./utils');
var isValidFormat = utils.isValidFormat;
var expect = require('code').expect;

process.setMaxListeners(0);


describe('cp-perms', function () {
  var actForSimpleMinded = {role: 'cp-test', cmd: 'acting_as_normal'};
  var actForAnybody = {role: 'cp-test', cmd: 'acting_as_free'};
  var actForAdult = {role: 'cp-test', cmd: 'acting_as_adult'};
  var actForPro = {role: 'cp-test', cmd: 'acting_as_pro'};
  var actForSchyzo = {role: 'cp-test', cmd: 'acting_as_schyzo'};

  var expectedResult = {'acting': 'as_normal'};
  var customValHandler = function (args, done) {
    var toTest = args.toTest;
    return done(null, {'allowed': toTest === 'imabanana'? true: false});
  };
  var spied = spy(customValHandler);
  seneca.add({role: 'cp-test', cmd: 'customVal'}, spied);

  lab.afterEach(function (done) {
    spied.reset();
    done();
  });

  it.skip('should create one act per "role" domain', function (done) {
    // We need to encapsulate w/ ready to ensure acts are added to seneca's list
    seneca.ready(function(){
      var acts = seneca.list();
      var filtered = _.filter(acts, {role: 'cp-test'});
      // +1 = customVal
      expect(filtered.length + 1).to.be.deep.equal(_.keys(conf['cp-test']).length);
      done();
    });
  });

  it('should disallow anonymous user', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, params : {}}, function (err, allowance) {
      expect(allowance).to.be.deep.equal({allowed: {status: 403}}).and.to.satisfy(isValidFormat);
      done();
    });
  });

  it('should allow anybody', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForAnybody.cmd, params: {}}, function (err, allowance) {
      expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
      done();
    });
  });

  it('should allow basic-user', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['basic-user']}}, function (err, allowance) {
      expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
      done();
    });
  });

  it('should allow with customValidators', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForPro.cmd, user: {roles: ['basic-user']}, toTest: 'imabanana'}, function (err, allowance) {
      expect(spied.callCount).to.be.equal(1);
      expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
      done();
    });
  });

  // TODO : seems to fail when used w/ others
  it.skip('should refuse with customValidators', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForPro.cmd, user: {roles: ['basic-user']}}, function (err, allowance) {
      expect(spied.callCount).to.be.equal(1);
      expect(allowance).to.be.deep.equal({allowed: {status: 401}}).and.to.satisfy(isValidFormat);
      done();
    });
  });

  it('should respect roleHierarchy', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['cdf-admin']}}, function (err, allowance) {
      expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
      done();
    });
  });

  it('should allow a list of profiles', function (done) {
    var basicUser = function (next) {
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['basic-user'], initUserType: ['parent']}, toTest: 'imabanana'}, function (err, allowance) {
        if (err) return done(err);
        expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        next();
      });
    };
    var cdfAdmin = function (next) {
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['cdf-admin']}}, function (err, allowance) {
        if (err) return done(err);
        expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        next();
      });
    };
    var mentor = function (next) {
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['basic-user'], initUserType: ['mentor']}, toTest: 'imabanana'}, function (err, allowance) {
        if (err) return done(err);
        expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        next();
      });
    };
    async.waterfall([basicUser, cdfAdmin, mentor], done);

  });

  /***** ERROR HANDLING ***/

  // TODO : test for missing conf
  // Apart from seneca errors, like act not found, or config errors (missing conf)
  it('should be not returning errors when userType does not exist', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['basic-userqsd']}}, function (err, allowance) {
      expect(allowance).to.satisfy(isValidFormat);
      expect(allowance).to.be.deep.equal({allowed: {status: 403}});
      done();
    });
  });

  it('should not be returning errors when passed params are in the wrong format', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: 'basic-user'}}, function (err, allowance) {
      expect(allowance).to.satisfy(isValidFormat);
      expect(allowance).to.be.deep.equal({allowed: true});
      done();
    });
  });

  // Since everything is casted to array, we can allow ourselves to simply send a sigle userType
  it('should be allowing a string instead of an array with a proper usertype', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: 'parent'}}, function (err, allowance) {
      expect(allowance).to.satisfy(isValidFormat);
      expect(allowance).to.be.deep.equal({allowed: true});
      done();
    });
  });

  it('should be refusing when using the usertype as a string instead of an array with a wrong usertype', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: 'attendee-o13'}}, function (err, allowance) {
      expect(allowance).to.satisfy(isValidFormat);
      expect(allowance).to.be.deep.equal({allowed: {status: 403}});
      done();
    });
  });

})
