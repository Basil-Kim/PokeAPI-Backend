
const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  endpointRequest: {
    type: String,
  },
  status: {
    type: Number,
  },
  user: {
    type: String,
  },
  url: {
    type: String
  },

  currentTime: {
    type: Date, 
    default: Date.now,
  },
  
  
});

const HistoryLog = mongoose.model('history', logSchema);
module.exports = HistoryLog