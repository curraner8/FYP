# https://portswigger.net/web-security/sql-injection#:~:text=The%20following%20code%20is%20vulnerable,%3D%20statement.executeQuery(query)%3B

String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
