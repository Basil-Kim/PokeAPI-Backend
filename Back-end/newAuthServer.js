const express = require('express')
const { handleErr } = require('./errorHandler.js')
const { asyncWrapper } = require('./asyncWrapper.js')
const dotenv = require('dotenv')
dotenv.config()
const userModel = require('./userModel.js')
const pokeModel = require('./models/pokemon.js')
const HistoryLog = require('./models/errorLog.js')

const mongoose = require('mongoose')
const cors = require('cors')
require('./db')

const {
  PokemonBadRequest,
  PokemonDbError,
  PokemonAuthError,
} = require('./errors.js')

const app = express()

const start = async () => {
  mongoose.connect(process.env.DB_STRING)

  app.listen(process.env.authServerPORT, async (err) => {
    if (err) throw new PokemonDbError(err)
    else
      console.log(
        `Phew! Server is running on port: ${process.env.authServerPORT}`,
      )
    try {
      const doc = await userModel.findOne({ username: 'admin' })

      if (!doc) {
        userModel.create({
          username: 'admin',
          password: bcrypt.hashSync('admin', 10),
          role: 'admin',
          email: 'admin@admin.ca',
        })
      }
    } catch (error) {
      
    }
  })
}

start()

app.use(express.json())
app.use(
  cors({
    exposedHeaders: ['Bearer', 'Refresh'],
  }),
)


const logEndpoint = (req, res, next) => {


  const logInfo = async () => {
    try {
      const str = `${req.url}`
      const url = str.indexOf('?') ? str : str.substring(0, str.indexOf('?'))

      const log = new HistoryLog({
        endpointRequest: `${req.method}`,
        status: Number(res.statusCode),
        user: req.body.username ? `${req.body.username}` : 'N/A',
        url: url,
      })

      await log.save()
    } catch (error) {
          }
  }

  logInfo()

  next()
}

app.use(logEndpoint)

const bcrypt = require('bcrypt')
app.post(
  '/register',
  asyncWrapper(async (req, res) => {
    const { username, password, email } = req.body
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    const userWithHashedPassword = { ...req.body, password: hashedPassword }

    const user = await userModel.create(userWithHashedPassword)
    res.status(200).json(hashedPassword)
  }),
)

const jwt = require('jsonwebtoken')
const Pokemon = require('./models/pokemon.js')

let refreshTokens = new Set() // replace with a db
app.post(
  '/requestNewAccessToken',
  asyncWrapper(async (req, res) => {
    
    const refreshToken = req.header('Refresh')
    if (!refreshToken) {
      throw new PokemonAuthError('No Token: Please provide a token.')
    }
    if (!refreshTokens.has(refreshToken)) {
      throw new PokemonAuthError('Invalid Token: Please provide a valid token.')
    }
    try {
      const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
      const accessToken = jwt.sign(
        { user: payload.user },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '1000s' },
      )

      await userModel.findByIdAndUpdate(
        { _id: payload.user._id },
        { token: accessToken, token_invalid: false },
      )

      res.header('Bearer', accessToken)
      res.status(200).json({ access: accessToken })
    } catch (error) {
      throw new PokemonAuthError('Invalid Token: Please provide a valid token.')
    }
  }),
)

app.post(
  '/login',
  asyncWrapper(async (req, res) => {
    const { username, password } = req.body
    const user = await userModel.findOne({ username })
    if (!user) throw new PokemonAuthError('User not found')

    const isPasswordCorrect = await bcrypt.compare(password, user.password)
    if (!isPasswordCorrect) throw new PokemonAuthError('Password is incorrect')

    const accessToken = jwt.sign(
      { _id: user._id, role: user.role },
      `${process.env.ACCESS_TOKEN_SECRET}`,
      { expiresIn: '1000s' },
    )

    const refreshToken = jwt.sign(
      { _id: user._id },
      `${process.env.REFRESH_TOKEN_SECRET}`,
      { expiresIn: '10000s' },
    )

    const tokens = {
      access: accessToken,
      refresh: refreshToken,
    }

    await userModel.findByIdAndUpdate(
      { _id: user._id },
      { token: accessToken, r_token: refreshToken, token_invalid: false },
    )

    refreshTokens.add(refreshToken)

    res.header('Bearer', accessToken)
    res.header('Refresh', refreshToken)

    const responseTokens = {
      refreshList: refreshTokens,
    }

    res.status(200).json(tokens)
  }),
)

app.post(
  '/logout',
  asyncWrapper(async (req, res) => {
    const { username } = req.body

    const user = await userModel.findOne({ username })
    if (!user) {
      throw new PokemonAuthError('User not found')
    }

    await userModel.findByIdAndUpdate(
      { _id: user._id },
      { token: user.token, token_invalid: true },
    )
    refreshTokens.delete(user.refreshToken)
    const responseTokens = {
      refreshList: refreshTokens,
    }


    res.status(200).json({
      tokens: responseTokens.refreshList,
      success: 'Logged out',
      userId: user._id,
    })
  }),
)

//
//
//RESOURCE ENDPOINTS
//
//

const morgan = require('morgan')

const messages = {
  noRoute: { msg: 'Improper route. Check API docs plz.' },
  success: { msg: 'Added Successfully' },
  notFound: { errMsg: 'Pokemon not found' },
  invalid: { errMsg: 'ValidationError: check your ...' },
  errMsg: { code: '11000' },
  castErr: { errMsg: 'Cast Error: pass pokemon id between 1 and 811' },
  successDelete: { msg: 'Deleted Successfully' },
}

app.use(express.json())

const authUser = asyncWrapper(async (req, res, next) => {
  // const to ken = req.header('auth-token')
  const token = req.header('Bearer') || req.header('auth-token')
  if (!token) {
    throw new PokemonAuthError('No Token: Please provide a header.')
  }
  const userWithToken = await userModel.findOne({ token })
  if (!userWithToken || userWithToken.token_invalid) {
    throw new PokemonAuthError('Please Login.')
  }
  try {
    
    const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET) // nothing happens if token is valid
    next()
  } catch (err) {
    throw new PokemonAuthError('Invalid user.')
  }
})

const authAdmin = asyncWrapper(async (req, res, next) => {
  const user = await userModel.findOne({ token: req.query.appid })

  if (user.role !== 'admin') {
    throw new PokemonAuthError('Access denied')
  }
  next()
})

/////////////////////////////////////////////////////////////////////
//            Limit the routes for normal users to GET             //
/////////////////////////////////////////////////////////////////////
app.use(morgan(':method'))
app.use(cors())
app.use(authUser)

app.get('/api/v1/pokemons', async (req, res) => {
  try {
    const pokemons = await Pokemon.find({})

    if (!pokemons) {
      return res.status(404).json({ error: 'Poke Not Found' })
    }
    return res.status(200).json(pokemons)
  } catch (error) {
    
    res.status(500).send(error)
  }
})

app.get('/api/v1/pokemon/:id', async (req, res) => {
  try {
    const pokemon = await Pokemon.find({ id: req.params.id })
    if (pokemon.length > 0) {
      return res.status(200).json(pokemon)
    } else {
      return res.status(404).json(messages.notFound)
    }
  } catch (error) {
    return res.status(400).json(messages.castErr)
  }
})

app.get('/api/v1/pokemonImage/:id', async (req, res) => {
  try {
    const reqId =
      typeof Number(req.params.id) == 'number' ? req.params.id : null
    const idQuery =
      reqId.length === 3
        ? reqId
        : reqId.length === 2
        ? '0' + reqId
        : reqId.length === 1
        ? '00' + reqId
        : null
    if (!reqId || idQuery > 809 || idQuery < 1) {
      return res.status(404).json({
        Error:
          'Image not found, please check that the number is between 1 and 809',
      })
    }
    res
      .status(200)
      .json(
        `https://github.com/fanzeyi/pokemon.json/blob/master/images/${idQuery}.png`,
      )
  } catch (error) {
    
  }
})

/////////////////////////////////////////////////////////////////////
//            Authorize Admins to have extra routes                //
/////////////////////////////////////////////////////////////////////

app.use(authAdmin)

app.post('/api/v1/pokemon', async (req, res) => {
  if (req.body.name.english.length >= 20) {
    return res.status(400).json(messages.invalid)
  }
  try {
    const existingId = await Pokemon.find({ id: req.body.id })
    if (existingId.length <= 0) {
      Pokemon.insertMany(req.body, (err, pokemons) => {
        if (err) return res.status(404).json(messages.invalid)
        return res.status(201).send(messages.success)
      })
    } else {
      const errorMessages = {
        errMsg: { code: 11000 },
      }
      return res.status(400).json(errorMessages)
    }
  } catch (error) {
    res.status(400).json(messages.invalid)
  }
})

app.delete('/api/v1/pokemon/:id', async (req, res) => {
  try {
    const pokemon = await Pokemon.findOneAndRemove({ id: req.params.id })
    if (pokemon) {
      const pokeStats = {
        pokeInfo: { id: req.params.id },
        msg: 'Deleted Successfully',
      }
      return res.status(200).json(pokeStats)
    } else {
      return res.status(404).json(messages.notFound)
    }
  } catch (error) {
    return res.status(500).send()
  }
})

app.patch('/api/v1/pokemon/:id', async (req, res) => {
  try {
    const exists = await Pokemon.find({ id: req.params.id })
    if (exists.length === 0) {
      return res.status(404).send({ error: 'Pokemon not found' })
    }
    const pokemon = await Pokemon.findOneAndUpdate(
      { id: req.params.id },
      { $set: req.body },
      { new: true },
    )
    const pokeStats = {
      msg: 'Updated Successfully',
      pokeInfo: {
        id: pokemon.id,
        base: {
          HP: pokemon.base.HP,
          Attack: pokemon.base.Attack,
        },
      },
    }
    res.status(200).json(pokeStats)
  } catch (error) {
    res.send({ error: error.message })
  }
})

app.put('/api/v1/pokemon/:id', async (req, res) => {
  try {
    const pokeExists = await Pokemon.find({ id: req.params.id })
    if (pokeExists.length === 0) {
      const errorMsg = {
        msg: 'Not found',
      }
      return res.status(404).json(errorMsg)
    } else {
      const pokemon = await Pokemon.findOneAndUpdate(req.params.id, req.body, {
        upsert: true,
        new: true,
        useFindAndModify: false,
        overwrite: true,
      })

      const pokeStats = {
        msg: 'Updated Successfully',
        pokeInfo: {
          id: pokemon.id,
          base: {
            HP: pokemon.base.HP,
            Attack: pokemon.base.Attack,
          },
        },
      }

      res.status(200).json(pokeStats)
    }
  } catch (error) {
    res.status(400).json(messages.invalid)
  }
})

app.get('/admin/logs/history', async (req, res) => {
  try {


    //unique users
    const uniqueUsers = await HistoryLog.aggregate([
      {
        $match: { user: { $ne: 'N/A' } },
      },
      {
        $group: {
          _id: {user: '$user'},
          count: { $sum: 1 },
          users: { $addToSet: '$user'},
        },
      },
      {
        $group: {
          _id: null,
          uniqueUsers: { $sum: 1 },
          maxCount: { $max: '$count' },
          users: {$first: '$user'},
        },
      },
    ])

    //Top User
    const topUser = await HistoryLog.aggregate([
      {
        $match: { user: { $ne: 'N/A' } },
      },
      {
        $group: {
          _id: {user: '$user' }, 
          count: { $sum: 1 }, 
        },
      },
      {
        $sort: { count: -1 }, 
      },
      {
        $limit: 1, 
      },
    ])

    //Date min/max
    const dateRange = await HistoryLog.aggregate([
      {
        $group: {
          _id: null,
          minDate: { $min: '$currentTime' },
          maxDate: { $max: '$currentTime' },
        },
      },
    ])

    const mostFrequentUsers = await HistoryLog.aggregate([
      
      {
        $match: { user: { $ne: 'N/A' } },
      },
      {
        $group: {
          _id: '$url', // group by the url field
          users: {
            $push: '$user', // add all the user values to an array
          },
          uniqueUsers: {
            $addToSet: '$user', // add each unique user value to a set
          },
        },
      },
      {
        $project: {
          _id: 1,
          uniqueUsers: { $size: '$uniqueUsers' }, // count the number of unique user values
          mostFrequentUser: {
            $first: '$users', // get the first array element (which has the most frequent user value)
          },
        },
      },
      {
        $sort: { uniqueUsers: -1 }, // sort by descending number of unique users
      },
    ]);


    const statusCounts = await HistoryLog.aggregate([
      {
        $match: { status: {   $gte: 400, $lte: 499   } }, // filter documents where status is 400 or 404
      },
      {
        $group: {
          _id: '$url', // group by the url field
          statuses: {
            $push: '$status', // add all the status values to an array
          },
        },
      },
    ]);

    const hourAgo = new Date(Date.now() - 60 * 60 * 1000); // get the date/time from an hour ago

const hourErrs = await HistoryLog.aggregate([
  {
    $match: {
      status: { $gte: 400, $lte: 500 }, // filter documents where status is between 400 and 500
      currentTime: { $gte: hourAgo }, // filter documents where currentTime is within the last hour
    },
  },
  {
    $group: {
      _id: '$url', // group by the url field
      statuses: {
        $push: '$status', // add all the status values to an array
      },
    },
  },
]);






    const response = {
      uniqueReport: uniqueUsers,
      date: dateRange,
      topUser: topUser,
      mostFrequentUsers: mostFrequentUsers,
      statusCounts: statusCounts,
      hourErrs: hourErrs,
    }

    res.status(200).json(response)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.get('*', (req, res) => {
  res.status(404).json({ error: 'No route exists' })
})

function logErrors(err, req, res, next) {
  // log the error
  
  // call the next middleware with the error

   const logInfo = async () => {
    try {
      const str = `${req.url}`
      const url = str.indexOf('?') ? str : str.substring(0, str.indexOf('?'))

      const log = new HistoryLog({
        endpointRequest: `${req.method}`,
        status: Number(err.pokeErrCode),
        user: 'N/A',
        url: url,
      })

      await log.save()
    } catch (error) {
      
    }
  }

  logInfo()


  next(err)
}

// middleware to log errors
app.use(logErrors)

//error handler for thrown errors
app.use(handleErr)

// Export the app.
module.exports = app
