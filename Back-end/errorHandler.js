const { mongoose } = require('mongoose');
const HistoryLog = require('./models/errorLog');
const handleErr = (err, req, res, next) => {
  if (err.pokeErrCode) res.status(err.pokeErrCode)
  else res.status(500)
  res.send(err.message)
  console.log('####################')
  console.log(err)
  console.log('####################')
  // if (err instanceof PokemonBadRequestMissingAfter) {
  //   res.status(err.code).send(err.message);
  // } else if (err instanceof PokemonBadRequestMissingID) {
  //   res.status(400).send(err.message);
  // } else {
  //   res.status(500).send(err.message);
  // }

  
}

module.exports = { handleErr }
