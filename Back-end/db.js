const mongoose = require('mongoose')
const axios = require('axios')
const dotenv = require('dotenv')
dotenv.config()
mongoose.connect(process.env.DB_STRING, { useNewUrlParser: true })
const HistoryLog = require('./models/errorLog')

const db = mongoose.connection

const options = { ordered: true }

const pokeDocs = async () => {
  try {
    const response = await axios(
      'https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/pokedex.json',
    )
    const data = response.data
    return data
  } catch (error) {
    console.error(error)
    return []
  }
}

db.on('error', console.error.bind(console, 'connection error:'))
db.once('open', () => {
  mongoose.connection.db.collection('pokemons').drop()
  console.log('Dropped pokemon table.')
  mongoose.connection.db
    .collection('pokemons')
    .count(async function (err, count) {
      const docs = await pokeDocs()
      if (count === 0) {
        db.collection('pokemons').insertMany(docs, options)
        console.log('pokemanz added')
      }
    })

  const createCollection = async () => {
    try {
      // Check if the collection already exists
      const collectionExists = await HistoryLog.exists()

      if (!collectionExists) {
        // Create the collection using the HistoryLog model
        HistoryLog.createCollection()
        console.log('Success in creating history collection')
      
      } else {
        console.log('History collection already exists')
      }
    
    } catch (error) {
      console.log(error)
    }
  }

  createCollection()
})

module.exports = db
