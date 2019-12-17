
EXEC=fim_db
SCHEMA=schema.o

$(EXEC): main.c $(EXEC).o sqlite3.o $(SCHEMA) dependencies.o
	@gcc -o $(EXEC) $^ -pthread -ldl -g

%.o: %.c
	@gcc -c -o $@ $^ -I./ -g

$(SCHEMA): schema_fim_db.sql
	@echo 'const char *schema_fim_sql = "'"`cat $< | tr -d \"\n\"`"'";' | gcc -xc -c -o $@ -

clean:
	@rm -f ./*.o $(EXEC)