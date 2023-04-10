
const mongoose = require('mongoose');
const axios = require('axios');

const pokemonSchema = new mongoose.Schema({
  id: { type: Number, unique: true, required: true },
  name: { 
    english: { 
      type: String, 
      max: 20, 
      validate: {
        validator: function(v) {
          return v.length <= 20;
        },
    message: "Name must be shorter than 20 characters"
  }} },
  base: {
    "HP": Number,
    "Attack": Number,
    "Defense": Number,
    "Speed": Number,
    "Sp. Attack": Number,
    "Sp. Defense": Number
  },
  type: {
    type: [{
      type: String,
      enum: [],
    }],
    required: true
  }
});

pokemonSchema.pre('save', async function() {
  console.log("Saved");
  
  if (!this.type.type.enum) {
    const response = await axios('https://raw.githubusercontent.com/fanzeyi/pokemon.json/master/types.json');
    const data = response.data;
    this.type.type.enum = data.map(i => i.english)
  }
}) 

const Pokemon = mongoose.model('pokemons', pokemonSchema);

module.exports = Pokemon;




