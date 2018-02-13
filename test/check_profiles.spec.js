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
var actForPro = {role: 'cp-test', cmd: 'acting_as_pro'};
var actForSchyzo = {role: 'cp-test', cmd: 'acting_as_schyzo'};
var actForCrazy = {role: 'cp-test', cmd: 'acting_as_crazy'};
var actUnderCtrl = {role: 'cp-test', ctrl: 'acting_under_ctrl', cmd: 'acting_as_normal_under_ctrl'};

describe('checkProfiles', () => {
  var { checkProfiles } = require('..');
  var customValHandler = (args, done) => {
    var toTest = args.toTest;
    return done(null, {'allowed': toTest === 'imabanana'});
  };
  var spied = spy(customValHandler);
  seneca.add({role: 'cp-test', cmd: 'customVal'}, spied);

  lab.afterEach((done) => {
    spied.reset();
    done();
  });

  it('should succeed if no profiles are given', (done) => {
    checkProfiles.call(seneca, [], {}, (err, res) => {
      expect(res.allowed).to.equal(true);
      done();
    })
  });

  it('should disallow anonymous user', (done) => {
    checkProfiles.call(seneca, [
        {
          role: 'basic-user'
        }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, params : {}},
      (err, res) => {
        expect(res).to.be.deep.equal({allowed: {status: 403}}).and.to.satisfy(isValidFormat);
        done();
      }
    );
  });

  it('should allow anybody', (done) => {
    checkProfiles.call(seneca, undefined,
      {role: 'cp-test', cmd: 'check_permissions', act: actForAnybody.cmd, params: {}},
      (err, res) => {
        expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        done();
      }
    );
  });

  it('should allow basic-user', (done) => {
    checkProfiles.call(seneca,
      [{ role: 'basic-user'}],
      {role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['basic-user']}},
      (err, res) => {
        expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        done();
      }
    );
  });

  it('should allow with customValidators', (done) => {
    checkProfiles.call(seneca, [
        {
          role: 'basic-user',
          customValidator: [
            {
              role: 'cp-test',
              cmd: 'customVal'
            }
          ]
        }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForPro.cmd, user: {roles: ['basic-user']}, toTest: 'imabanana'},
      (err, res) => {
        expect(spied.callCount).to.be.equal(1);
        expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        done();
      }
    );
  });

  // TODO : seems to fail when used w/ others
  it('should refuse with customValidators', (done) => {
    checkProfiles.call(seneca, [
        {
          role: 'basic-user',
          customValidator: [
            {
              role: 'cp-test',
              cmd: 'customVal'
            }
          ]
        }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForPro.cmd, user: {roles: ['basic-user']}},
      (err, res) => {
        expect(spied.callCount).to.be.equal(1);
        expect(res).to.be.deep.equal({allowed: {status: 401}}).and.to.satisfy(isValidFormat);
        done();
      }
    );
  });

  it('should respect roleHierarchy', (done) => {
    checkProfiles.call(seneca, [
        {
          role: 'basic-user'
        }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['cdf-admin']}},
      (err, res) => {
        expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
        done();
      }
    );
  });

  it('should allow a list of profiles', (done) => {
    const profiles = [
      {
        role: 'basic-user',
        userType: 'parent-guardian',
        customValidator: [
          {
            role: 'cp-test',
            cmd: 'customVal'
          }
        ]
      },
      {
        role: 'cdf-admin',
      },
      {
        role: 'basic-user',
        userType: 'mentor',
        customValidator: [{
            role: 'cp-test',
            cmd: 'customVal'
        }]
      }
    ];
    var basicUser = (next) => {
      checkProfiles.call(seneca, profiles,
        {role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['basic-user'], initUserType: ['parent-guardian']}, toTest: 'imabanana'},
        (err, res) => {
          if (err) return done(err);
          expect(spied.calledOnce).to.be.true;
          expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
          next();
        }
      );
    };
    var cdfAdmin = (next) => {
      checkProfiles.call(seneca, profiles,
        {role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['cdf-admin']}},
        (err, res) => {
          if (err) return done(err);
          expect(spied.calledOnce).to.be.true;
          expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
          next();
        }
      );
    };
    var mentor = (next) => {
      checkProfiles.call(seneca, profiles,
        {role: 'cp-test', cmd: 'check_permissions', act: actForSchyzo.cmd, user: {roles: ['basic-user'], initUserType: ['mentor']}, toTest: 'imabanana'},
        (err, res) => {
          if (err) return done(err);
          expect(spied.calledOnce).to.be.true;
          expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
          next();
        }
      );
    };
    async.waterfall([basicUser, cdfAdmin, mentor], done);

  });

  // In this scenario, we set a scenario where only the last customVal is valid in order to verify that every customVal is called
  it('should allow a list of profiles with multiple customVals', (done) => {
    const profiles = [
      {
        role: 'basic-user',
        userType: 'parent-guardian',
        customValidator: [
          {
            role: 'cp-test',
            cmd: 'customVal'
          },
          {
            role: 'cp-test',
            cmd: 'customValSSW'
          }
        ]
      },
      {
        role: 'cdf-admin'
      },
      {
        role: 'basic-user',
        userType: 'mentor',
        customValidator: [
          {
            role: 'cp-test',
            cmd: 'customValSSW'
          },
          {
            role: 'cp-test',
            cmd: 'customValCIHCB'
          }
        ]
      }
    ];
    // Setup spies
    var customValHandler2 = (args, done) => {
      var toTest = args.toTest2;
      return done(null, {'allowed': toTest === 'sicksadworld'});
    };
    var spyHandler2 = spy(customValHandler2);
    seneca.add({role: 'cp-test', cmd: 'customValSSW'}, spyHandler2);

    var customValHandler3 = (args, done) => {
      var toTest = args.toTest3;
      return done(null, {'allowed': toTest === 'canihazcheezburger'});
    };
    var spyHandler3 = spy(customValHandler3);
    seneca.add({role: 'cp-test', cmd: 'customValCIHCB'}, spyHandler3);

    // Do the calls !
    var basicUser = (next) => {
      checkProfiles.call(seneca, profiles,
        {
          role: 'cp-test',
          cmd: 'check_permissions',
          act: actForCrazy.cmd,
          user: { roles: ['basic-user'], initUserType: ['parent-guardian']},
          toTest: 'imabanana',
          toTest2: 'sicksadworld'
        }, (err, res) => {
          if (err) return done(err);
          expect(spied.calledOnce).to.be.true;
          expect(spyHandler2.calledOnce).to.be.true;
          expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
          next();
        }
      );
    };
    var cdfAdmin = (next) => {
      checkProfiles.call(seneca, profiles,
        {role: 'cp-test', cmd: 'check_permissions', act: actForCrazy.cmd, user: {roles: ['cdf-admin']}},
        (err, res) => {
          if (err) return done(err);
          expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
          next();
        }
      );
    };
    var mentor = (next) => {
      checkProfiles.call(seneca, profiles,
        {role: 'cp-test', cmd: 'check_permissions', act: actForCrazy.cmd, user: {roles: ['basic-user'], initUserType: ['mentor']}, toTest2: 'sicksadworld',  toTest3: 'canihazcheezburger'},
        (err, res) => {
          if (err) return done(err);
          expect(spyHandler2.callCount).to.be.equal(3); // basicUser 1st profile + this call basic-user 1st profile + this call last profile
          expect(spyHandler3.callCount).to.be.equal(1);
          expect(res).to.be.deep.equal({allowed: true}).and.to.satisfy(isValidFormat);
          next();
        }
      );
    };
    async.waterfall([
      basicUser,
      cdfAdmin,
      mentor
    ], done);

  });

  /***** ERROR HANDLING ***/

  // TODO : test for missing conf
  // Apart from seneca errors, like act not found, or config errors (missing conf)
  it('should be not returning errors when userType does not exist', (done) => {
    checkProfiles.call(seneca, [
        { role: 'basic-user' }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: ['basic-userqsd']}},
      (err, res) => {
        expect(res).to.satisfy(isValidFormat);
        expect(res).to.be.deep.equal({allowed: {status: 403}});
        done();
      }
    );
  });

  it('should not be returning errors when passed params are in the wrong format', (done) => {
    checkProfiles.call(seneca, [
        { role: 'basic-user' }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForSimpleMinded.cmd, user: {roles: 'basic-user'}},
      (err, res) => {
        expect(res).to.satisfy(isValidFormat);
        expect(res).to.be.deep.equal({allowed: true});
        done();
      }
    );
  });

  // Since everything is casted to array, we can allow ourselves to simply send a sigle userType
  it('should be allowing a string instead of an array with a proper usertype', (done) => {
    checkProfiles.call(seneca, [
        { userType: 'champion' },
        { userType: 'mentor' },
        { userType: 'parent-guardian' }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: 'parent-guardian'}},
      (err, allowance) => {
        expect(allowance).to.satisfy(isValidFormat);
        expect(allowance).to.be.deep.equal({allowed: true});
        done();
      }
    );
  });

  it('should be refusing when using the usertype as a string instead of an array with a wrong usertype', (done) => {
    checkProfiles.call(seneca, [
        { userType: 'champion' },
        { userType: 'mentor' },
        { userType: 'parent-guardian' }
      ],
      {role: 'cp-test', cmd: 'check_permissions', act: actForAdult.cmd, user: {initUserType: 'attendee-o13'}},
      (err, allowance) => {
        expect(allowance).to.satisfy(isValidFormat);
        expect(allowance).to.be.deep.equal({allowed: {status: 403}});
        done();
      }
    );
  });
});