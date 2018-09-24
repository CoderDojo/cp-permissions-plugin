'use strict';
var seneca = require('seneca')();
seneca.use(require('..'), {
  config: __dirname + '/permissions-rules'});
var _lab = require('lab');
var _ = require('lodash');
var async = require('async');
var sinon = require('sinon');
var spy = sinon.spy;
var conf = require('./permissions-rules')();
var lab = exports.lab = _lab.script();
var describe = lab.describe;
var it = lab.it;
var utils = require('./utils');
var isValidFormat = utils.isValidFormat;
var expect = require('code').expect;

var actForSimpleMinded = {role: 'cp-test', cmd: 'acting_as_normal'};
var actForAnybody = {role: 'cp-test', cmd: 'acting_as_free'};
var actForAdult = {role: 'cp-test', cmd: 'acting_as_adult'};
var actForChildren = {role: 'cp-test', cmd: 'acting_as_children'};
var actForPro = {role: 'cp-test', cmd: 'acting_as_pro'};
var actForSchyzo = {role: 'cp-test', cmd: 'acting_as_schyzo'};
var actForCrazy = {role: 'cp-test', cmd: 'acting_as_crazy'};
var actUnderCtrl = {role: 'cp-test', ctrl: 'acting_under_ctrl', cmd: 'acting_as_normal_under_ctrl'};

process.setMaxListeners(0);


describe('cp-perms', function () {

  var expectedResult = {'acting': 'as_normal'};
  var customValHandler = function (args, done) {
    var toTest = args.toTest;
    return done(null, {'allowed': toTest === 'imabanana'});
  };
  var spied = spy(customValHandler);
  seneca.add({role: 'cp-test', cmd: 'customVal'}, spied);

  lab.afterEach(function (done) {
    spied.reset();
    done();
  });

  it('should create one act per "role" domain', function (done) {
    // We need to encapsulate w/ ready to ensure acts are added to seneca's list
    seneca.ready(function(){
      var acts = seneca.list();
      var filtered = _.filter(acts, {role: 'cp-test'});
      expect(filtered.length).to.be.deep.equal(_.keys(conf).length + 1); // 1 = number of custom validators
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
  
  it('should allow the lowest user-type', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForChildren.cmd, user: {roles: ['basic-user'], initUserType: ['attendee-o13'] }}, function (err, allowance) {
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
  it('should refuse with customValidators', function (done) {
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
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['basic-user'], initUserType: ['parent-guardian']}, toTest: 'imabanana'}, function (err, allowance) {
        if (err) return done(err);
        expect(spied.calledOnce).to.be.true;
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

  // In this scenario, we set a scenario where only the last customVal is valid in order to verify that every customVal is called
  it('should allow a list of profiles with multiple customVals', function (done) {
    // Setup spies
    var customValHandler2 = function (args, done) {
      var toTest = args.toTest2;
      return done(null, {'allowed': toTest === 'sicksadworld'});
    };
    var spyHandler2 = spy(customValHandler2);
    seneca.add({role: 'cp-test', cmd: 'customValSSW'}, spyHandler2);

    var customValHandler3 = function (args, done) {
      var toTest = args.toTest3;
      return done(null, {'allowed': toTest === 'canihazcheezburger'});
    };
    var spyHandler3 = spy(customValHandler3);
    seneca.add({role: 'cp-test', cmd: 'customValCIHCB'}, spyHandler3);

    // Do the calls !
    var basicUser = function (next) {
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForCrazy.cmd, user: {roles: ['basic-user'], initUserType: ['parent-guardian']},
       toTest: 'imabanana', toTest2: 'sicksadworld'}, function (err, allowance) {
        if (err) return done(err);
        expect(spied.calledOnce).to.be.true;
        expect(spyHandler2.calledOnce).to.be.true;
        expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        next();
      });
    };
    var cdfAdmin = function (next) {
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForCrazy.cmd, user: {roles: ['cdf-admin']}}, function (err, allowance) {
        if (err) return done(err);
        expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        next();
      });
    };
    var mentor = function (next) {
      seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForCrazy.cmd, user: {roles: ['basic-user'], initUserType: ['mentor']}, toTest2: 'sicksadworld',  toTest3: 'canihazcheezburger'}, function (err, allowance) {
        if (err) return done(err);
        expect(spyHandler2.callCount).to.be.equal(3); // basicUser 1st profile + this call basic-user 1st profile + this call last profile
        expect(spyHandler3.callCount).to.be.equal(1);
        expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        next();
      });
    };
    async.waterfall([
      basicUser,
      cdfAdmin,
      mentor
    ], done);

  });

  it('should not modify the config after all those calls', function (done) {
    expect(conf).to.be.deep.equal(seneca.export('cd-permissions/config'));
    done();
  });

  /***** ERROR HANDLING ***/

  // TODO : test for missing conf
  // Apart from seneca errors, like act not found, or config errors (missing conf)
  it('should be not returning errors when role does not exist', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['basic-userqsd']}}, function (err, allowance) {
      expect(allowance).to.satisfy(isValidFormat);
      expect(allowance).to.be.deep.equal({allowed: {status: 403}});
      done();
    });
  });
  
  it('should be not returning errors when userType does not exist', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: ['monster-munch']}}, function (err, allowance) {
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
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: 'parent-guardian'}}, function (err, allowance) {
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

  it('should allow basic-user under a ctrl', function (done) {
    seneca.act({role: 'cp-test', cmd: 'check_permissions', act: actUnderCtrl.cmd, params: { ctrl: actUnderCtrl.ctrl }, user: {roles: ['basic-user']}}, function (err, allowance) {
      expect(allowance).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
      done();
    });
  });

});
