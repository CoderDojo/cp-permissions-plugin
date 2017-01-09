module.exports = function () {

/*
* Format of a permission {
* role: 'basic-user' || {'basic-user':{match: true}}
* customValidator: functionName
* }
*/

//  TODO:50 ensure is_own_dojo for dojo-admin && belongs_to for champion

  return {
    'cp-test':{
      'acting_as_normal': [{
        role: 'basic-user'
      }],
      'acting_as_adult': [{
        userType: 'champion'
      },
      {
        userType: 'mentor'
      },
      {
        userType: 'parent'
      }],
      'acting_as_pro': [{
        role: 'basic-user',
        customValidator: [{
            role: 'cp-test',
            cmd: 'customVal'
        }]
      }],
      'acting_as_schyzo': [{
        role: 'basic-user',
        userType: 'parent',
        customValidator: [{
            role: 'cp-test',
            cmd: 'customVal'
        }]
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
      ]
    }
  };
};
