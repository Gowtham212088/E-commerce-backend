                                              MONGO DB

# Creating a new Database

- If there is no database in that name, MongoDB will create on its own

I) db(dbName).collection(collectionName).insertOne(variable)

# Dropping a Database

- use db, then db.dropDatabase()

# Creating a collection

- db.createCollection("collectionName")

# Dropping a collection

- db.collectionName.drop()

# Data Types in MongoDb

- BSON -> Binary encoded JSON is known as BSON.
- JSON
- INTEGER
- BOOLEAN
- DOUBLE
- ARRAYS
- OBJECT
- NULL
- DATE
- TIME STAMP
- OBJECT ID
- CODE

- We can chenge the BSON \_id, But its not a good practices.

                         CREATE METHOD

# insert documents into collections

- Insert single

  - db.collectionName.insert({"name":"Gowtham"})
    (or)
  - db.collectionName.insertOne({"name":"Gowtham"})

// used to add a new object in a collection

- Insert Many

  - db.collectionName.insertMany([{"key":"value",
    "key1":"value1"},{"key2":"value2","key3":"value3"}])

                                UPDATE METHOD

  # Updating Documents which are already existing in a collection (UPDATEONE, UPDATEMANY, REPLACEONE)

  - UPDATE

// used to update a xtra key value pairs on existing object which matches.

    * db.collectionName.update({reference key value pair},{$set:{mobile:"1234567890","isActive":true}})

    - updateMany

// used to update a datas in multiple documents, where it matches, and also we can add xtra key value pairs those documents.

    * db.collectionName.updateMany({"isActive":true},{$set:{"isActive":false}})

    * db.collectionName.updateMany({"isActive":true},{$set:{"rollno":"nil"}}) // extra key value pair added.

    - REPLACEONE

     // It uses the 1st arguement as query & Then 2nd arguement as a replacement.

    * db.collectionName.replaceOne({query(keyvalue pair)},{replacement(keyvalue pair)})

# Read the documents:(GET)

- db.collection.find()  // Shows the complete datas
- db.collection.findOne() // Shows the single document in collection
- db.collection.findOneAndReplace({find},replace{}) // It completly replaces the entire document not just the key value pair.
- db.collection.findOneAndDelete({}) // It will find and delete the complete document
OPERATORS USED : 

# EQUALITY
# LESSER THAN 
# LESSER THAN EQUAL
# GRATER THAN
# LESSER THAN EQUAL
# NOT EQUAL

- SELECTING FIELDS (We need to specify the fields 1)

       
 

