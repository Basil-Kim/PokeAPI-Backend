const express = require('express')
const { handleErr } = require('./errorHandler.js')
const { asyncWrapper } = require('./asyncWrapper.js')
const dotenv = require('dotenv')
dotenv.config()
const userModel = require('./userModel.js')
const mongoose = require('mongoose')
const cors = require('cors')

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
    const doc = await userModel.findOne({ username: 'admin' })
    if (!doc)
      userModel.create({
        username: 'admin',
        password: bcrypt.hashSync('admin', 10),
        role: 'admin',
        email: 'admin@admin.ca',
      })
  })
}

start()

app.use(express.json())
app.use(
  cors({
    exposedHeaders: ['Bearer', 'Refresh'],
  }),
)

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
app.post('/requestNewAccessToken', asyncWrapper(async (req, res) => {
  // console.log(req.headers);
  const refreshToken = req.header('Refresh')
  if (!refreshToken) {
    throw new PokemonAuthError("No Token: Please provide a token.")
  }
  if (!refreshTokens.has(refreshToken)) { // replaced a db access
    
    throw new PokemonAuthError("Invalid Token: Please provide a valid token.")
  }
  try {
    const payload = await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
    const accessToken = jwt.sign({ user: payload.user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '10s' })
    res.header('Bearer', accessToken)
    res.status(200).json({access: accessToken})
  } catch (error) {
    throw new PokemonAuthError("Invalid Token: Please provide a valid token.")
  }
}))


app.post('/login', asyncWrapper(async (req, res) => {
  const { username, password } = req.body
  const user = await userModel.findOne({ username })
  if (!user)
    throw new PokemonAuthError("User not found")

  const isPasswordCorrect = await bcrypt.compare(password, user.password)
  if (!isPasswordCorrect)
    throw new PokemonAuthError("Password is incorrect")



  const accessToken = jwt.sign({ _id: user._id, role: user.role}, `${process.env.ACCESS_TOKEN_SECRET}`, { expiresIn: '10s' })
  const refreshToken = jwt.sign({ _id: user._id }, `${process.env.REFRESH_TOKEN_SECRET}`, { expiresIn: '10000s'})

  const tokens = {
    access: accessToken,
    refresh: refreshToken
  }


  await userModel.findByIdAndUpdate({_id: user._id}, {token: accessToken, r_token: refreshToken, token_invalid: false})
  refreshTokens.add(refreshToken)

  res.header('Bearer', accessToken)
  res.header('Refresh', refreshToken)

  const responseTokens = {
    refreshList: refreshTokens
  }

  console.log(`This is the array for refresh tokens ${refreshTokens}`);
  res.status(200).json(responseTokens);
}))





app.get(
  '/logout',
  asyncWrapper(async (req, res) => {
    const { username } = req.body
    const user = await userModel.findOne({username})
    if (!user) {
      throw new PokemonAuthError('User not found')
    }
    // await userModel.updateOne({ token: user.token }, { token_invalid: true })
    // res.status(200).json({success: 'Logged out'})

    await userModel.findByIdAndUpdate({_id: user._id}, {token: user.token, token_invalid: true})
    refreshTokens.delete(user.refreshToken)
    const responseTokens = {
      refreshList: refreshTokens
    }
    // console.log(`This is the array for refresh tokens ${
    //   refreshTokens
    // }`);

    for (const item of refreshTokens.values()) {
      console.log(item);
    }

    res.status(200).json({tokens: responseTokens.refreshList, success: 'Logged out', userId: user._id});
  })
)
app.get('*', (req, res) => {
  res.status(404).json({error: "No route exists"})
})
app.use(handleErr)

module.exports = app;