const express = require('express');
const app = express();
const port = 8083;
const { Client } = require('pg');
const pug = require('pug');

app.use(express.static('static'));
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));

const client = new Client({ //Вставьте свои параметры БД
    user: 'postgres',
    host: 'localhost',
    database: 'lib',
    password: '12345',
    port: 5432,
});
client.connect();

app.set('view engine', 'pug');

app.get('/', (req, res) => {
  res.redirect('/login.html');
})

app.get('/books', async (req, res) => {
    const rawCookies = req.headers;
    let bookname = req.query.name;

    var url = require('url');
    var url_parts = url.parse(req.url, true);
    var query = url_parts.query;
   /* let sql = `select ba.id, a.name as author, b.name as book from books_by_authors ba
                  left join author a on a.id = ba.aid
                  left join book b on b.id = ba.bid where b.name like '%${bookname}%'`;*/

    let sql = `select ba.id, a.name as author, b.name as book from books_by_authors ba
                  left join author a on a.id = ba.aid
                  left join book b on b.id = ba.bid`;

    let result = bookname.indexOf('\'');
    if ( result >= 0 ) {
        bookname = 'Неподходящее условие';
        //res.send('Неподходящее условие');
    }
    else {

            if (bookname) {
                sql += `\rwhere b.name like '%${bookname}%'`
            }
    }

    try{
        let data = await client.query(sql);
        res.render('booklist', {data: data.rows,filter: bookname});
    }
    catch(e)
    {
        console.log(e);
        res.send(`error ${e.message}. <br/> SQL:${sql}`);
    }
    
})

app.post('/signin', async (req, res) => {
    let login = req.body.name;
    let pass = req.body.pass;
   // let sql = "SELECT name as result FROM users WHERE name = '" + login + "' AND pass = md5('" + pass + "')";
    let sql = {
        text: "SELECT name as result FROM users WHERE name = $1 AND pass = md5($2)"
        ,values: [login, pass]
    };
    try{
        let data = await client.query(sql);
        let userId = data.rows[0].result;
        if(data.rows.length>0  && data.rows[0].result){
            const oneDaytoSeconds = 24*60*60;
            res.redirect('/books');
        }else
        {
            res.send(`fail ${login}`);
        }
    }
    catch(e)
    {
        console.log(e);
        res.send(`error ${e.message}. <br/> SQL:${sql}`);
    }

  })


app.listen(port, ()=>{
	console.log(`server running at http://localhost:${port}`);
})
