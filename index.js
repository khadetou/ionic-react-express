const express = require("express");
const cors = require("cors");
const loginRouter = require("./routes/login");

const app = express();

app.use(cors());

app.use("/login", loginRouter);

app.listen(3000, () => console.log("Server is running ..."));
