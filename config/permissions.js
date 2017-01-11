module.exports = function () {
  return {
      roles: ['none', 'basic-user', 'cdf-admin'],
      userTypes: ['attendee-u13', 'attendee-o13', 'parent-guardian', 'mentor'],
      roleHierarchy: {
        'cdf-admin': {
          'basic-user': {
            'none': {}
          }
        }
      },
      userTypeHierarchy: {
        'basic-user': {
          'champion': [{
            'parent-guardian': [
              {'attendee-o13': {}},
              {'attendee-u13': {}}
              ]
            },
            {'mentor': {}}
            ]
          }
      },
    };

};
