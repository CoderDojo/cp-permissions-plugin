var _ = require('lodash');
module.exports = {
  isValidFormat: function (payload) {
    if (_.isObject(payload)) {
      if (_.has(payload, 'allowed')) { // allowed can then be an object or a boolean
        return true;
      }
    }
    return false;
  }
};
