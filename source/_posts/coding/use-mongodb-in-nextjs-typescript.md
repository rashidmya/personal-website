---
title: Use MongoDB with TypeScript in Next.js
date: 2023-10-23 13:57:21
tags: 
    - mongodb
    - nextjs
    - typescript
category: coding
---
This solves the `OverwriteModelError` error when using mongodb with nextjs & typescript

## Setting up MongoDB

### Declare global types
Create a *mongodb.ts* file in your **@types** folder to declare global mongoose variables
```typescript @\@types\mongodb.ts 
import { Mongoose } from 'mongoose';

/* eslint-disable no-var */

declare global {
  var mongoose: {
    promise: Promise<Mongoose> | null;
    conn: Mongoose | null;
  };
}
```

<br>

### Create util
Create a file called *mongodb.ts* in your **utils** folder to use to connect the the database
```typescript @\utils\mongodb.ts 
import mongoose from 'mongoose';

const { MONGODB_URI, MONGODB_DB } = process.env;

if (!MONGODB_URI) throw new Error('MONGODB_URI not defined');
if (!MONGODB_DB) throw new Error('MONGODB_DB not defined');

let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = {conn: null, promise: null}
}

async function dbConnect() {
  if (cached.conn) return cached.conn;

  if (!cached.promise) {
    cached.promise = mongoose.connect(`${MONGODB_URI}/${MONGODB_DB}`).then(mongoose => mongoose)
  }

  cached.conn = await cached.promise;
  return cached.conn
}

export default dbConnect;
```

<br>

### Create Schema
Create a simple user model
```typescript @\models\user.model.ts 
import { models, model, Schema } from 'mongoose';

const UserSchema: Schema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  displayName: {
    type: String,
    required: true,
  }
});

const UserModel = models.User || model('User', UserSchema);

export default UserModel
```

<br>

### API
After setting up the types, connection util and user model, we can now create our api.
```javascript @\pages\api\users.ts 
import dbConnect from '@/utils/mongodb';
import UserModel from '@/models/user.model';

// ----------------------------------------------------------------------

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    dbConnect();
    const users = UserModel;
    
    const allUsers = await users.find({});

    res.status(200).json({ users: allUsers });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
}
```