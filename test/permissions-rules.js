module.exports = function () {

/*
* Format of a permission {
* role: 'basic-user' || {'basic-user':{match: true}}
* customValidator: functionName
* }
*/


  return {
    'cp-test':{
      'acting_as_normal': [
        {
          role: 'basic-user'
        }
      ],
      'acting_as_adult': [
        {
          userType: 'champion'
        },
        {
          userType: 'mentor'
        },
        {
          userType: 'parent-guardian'
        }
      ],
      'acting_as_children': [
        {
          userType: 'attendee-o13'
        },
      ],
      'acting_as_pro': [
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
      'acting_as_schyzo': [
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
      ],
      'acting_as_crazy': [
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
      ],
      'acting_under_ctrl': {
        'acting_as_normal_under_ctrl': [
          {
            role: 'basic-user'
          }
        ]
      }
    }
  };
};
