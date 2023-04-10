const express = require("express");
const Pokemon  = require("./models/pokemon");
const app = express();
const {asyncWrapper} = require("./asyncWrapper.js");
const morgan = require("morgan");
const cors = require("cors");
const { handleErr } = require("./errorHandler.js")

const {
  PokemonBadRequest,
  PokemonBadRequestMissingID,
  PokemonBadRequestMissingAfter,
  PokemonDbError,
  PokemonNotFoundError,
  PokemonDuplicateError,
  PokemonNoSuchRouteError,
  PokemonAuthError
} = require("./errors.js")

const messages = {
  noRoute: {msg: "Improper route. Check API docs plz."},
  success: {msg: "Added Successfully"},
  notFound: {errMsg: "Pokemon not found"},
  invalid: {errMsg: "ValidationError: check your ..."},
  errMsg: { code: "11000"},
  castErr: {errMsg: "Cast Error: pass pokemon id between 1 and 811"},
  successDelete: {msg: "Deleted Successfully"},
}


app.use(express.json());

// Authorization middleware
const jwt = require("jsonwebtoken");
const userModel = require("./userModel.js");
const dotenv = require("dotenv");
dotenv.config();

const authUser = asyncWrapper(async (req, res, next) => {
  // const to ken = req.header('auth-token')
  const token = req.header('Bearer')
  if (!token) {
    throw new PokemonAuthError("No Token: Please provide a header.")
  }
  const userWithToken = await userModel.findOne({ token })
  if (!userWithToken || userWithToken.token_invalid) {
    throw new PokemonAuthError("Please Login.")
  }
  try {
    // console.log("token: ", token);
    const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET) // nothing happens if token is valid
    next()
  } catch (err) {
    throw new PokemonAuthError("Invalid user.")
  }
})

const authAdmin = asyncWrapper(async (req, res, next) => {
  const user = await userModel.findOne({ token: req.query.appid })
  
  if (user.role !== "admin") {
    throw new PokemonAuthError("Access denied")
  }
  next()
})

/////////////////////////////////////////////////////////////////////
//            Limit the routes for normal users to GET             //
/////////////////////////////////////////////////////////////////////
app.use(morgan(":method"));
app.use(cors());
app.use(authUser);


app.get('/api/v1/pokemons', async (req, res) => {
  try {
    const count = req.query.count ? parseInt(req.query.count) : 2;
    const after = req.query.after ? parseInt(req.query.after) : 10;
    const pokemons = await Pokemon.find().skip(after).limit(count);
    return res.status(200).json(pokemons);
    
  } catch(error) {
    console.log(error);
    res.status(500).send(error);  
  }
});


  app.get('/api/v1/pokemon/:id', async (req, res) => {
      try {
          const pokemon = await Pokemon.find({id: req.params.id});
          if (pokemon.length>0) {
            return res.status(200).json(pokemon);
          } else {
            return res.status(404).json(messages.notFound);
          }
      } catch (error) {
          return res.status(400).json(messages.castErr);
      }
  });

app.get('/api/v1/pokemonImage/:id', async (req, res) => {
  try {
    const reqId = typeof Number(req.params.id) == 'number' ? req.params.id : null;
    const idQuery = reqId.length === 3 ? reqId : reqId.length === 2 ? '0'+reqId : reqId.length === 1 ? '00'+reqId : null;
    if (!reqId || idQuery > 809 || idQuery < 1) {
      return res.status(404).json({Error: "Image not found, please check that the number is between 1 and 809"})
    } 
    res.status(200).json(`https://github.com/fanzeyi/pokemon.json/blob/master/images/${idQuery}.png`)
  } catch (error) {
    console.log(error);
  }
})  

app.get('*', (req, res) => {
  res.status(404).send(messages.noRoute)
})


/////////////////////////////////////////////////////////////////////
//            Authorize Admins to have extra routes                //
/////////////////////////////////////////////////////////////////////

app.use(authAdmin)


app.post('/api/v1/pokemon', async (req, res) => {
  if (req.body.name.english.length >= 20) {
    return res.status(400).json(messages.invalid);
  }
  try {
    const existingId = await Pokemon.find({id: req.body.id});
    if (existingId.length <= 0) {
        Pokemon.insertMany(req.body, (err, pokemons) => {
        if (err) return res.status(404).json(messages.invalid);
        return res.status(201).send(messages.success);
      })
    } else {
      const errorMessages = {
        errMsg: {code: 11000}
      }
        return res.status(400).json(errorMessages);
    }
  } catch (error) {
    res.status(400).json(messages.invalid);
  }  
})

app.delete('/api/v1/pokemon/:id', async (req, res) => {
  try {
    const pokemon = await Pokemon.findOneAndRemove({ id: req.params.id });
    if (pokemon) {
      const pokeStats = {
        pokeInfo: {id: req.params.id},
        msg: "Deleted Successfully",
      }
      return res.status(200).json(pokeStats);
    } else {
      return res.status(404).json(messages.notFound);
    }
  } catch (error) {
    return res.status(500).send();
  }
});


app.patch('/api/v1/pokemon/:id', async (req, res) => {
  try {
    const exists = await Pokemon.find({id: req.params.id});
    if (exists.length===0) {
      return res.status(404).send({ error: 'Pokemon not found' });
    }     
    const pokemon = await Pokemon.findOneAndUpdate(
      { id: req.params.id },
      { $set: req.body },
      { new: true }
    );
    const pokeStats = {
      msg: "Updated Successfully",
      pokeInfo: {
        id: pokemon.id,
        base: {
          HP: pokemon.base.HP,
          Attack: pokemon.base.Attack
        }          
      },
    };
    res.status(200).json(pokeStats);  
  } catch (error) {
    res.send({ error: error.message });
  }
}) 

app.put('/api/v1/pokemon/:id', async (req, res) => {
    try {
      const pokeExists = await Pokemon.find({id: req.params.id});
      if (pokeExists.length === 0) {
        const errorMsg = {
          msg: "Not found"
        };
        return res.status(404).json(errorMsg);
      } else {
      const pokemon = await Pokemon.findOneAndUpdate(
        req.params.id,
        req.body,
        { upsert: true, new: true, useFindAndModify: false, overwrite: true}
      );
      const pokeStats = {
        msg: "Updated Successfully",
        pokeInfo: {
          id: pokemon.id,
          base: {
            HP: pokemon.base.HP,
            Attack: pokemon.base.Attack
          }          
        },
      }
      res.status(200).json(pokeStats);
    }
  } catch (error) {
    res.status(400).json(messages.invalid);
  }
})



function logErrors(err, req, res, next) {
  // log the error
  console.error(err.stack)
  // call the next middleware with the error
  next(err)
}

// middleware to log errors
app.use(logErrors)

//error handler for thrown errors
app.use(handleErr)

// Export the app.
module.exports = app;