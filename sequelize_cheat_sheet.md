# Sequelize cheat Sheet

### GENERATE A MODEL WITH ROWS

```
 npx sequelize-cli model:generate --name User --attributes firstName:String,lastName:string,email:string
```

### MIGRATE THE MODELS CHANGES INTO THE DB

```
 node_modules/.bin/sequelize db:create
 node_modules/.bin/sequelize db:migrate
```
