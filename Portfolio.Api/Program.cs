using System.ComponentModel.DataAnnotations;

builder.Services.AddSqlServer<>

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.MapGet("/", (Contact contact) =>
{

})
.WithOpenApi();

app.Run();

public class Contact
{
    public Guid Id { get; set; }
    public string Name { get; set; }

    public string Email { get; set; }
    public string Subject { get; set; }
    public string Message { get; set; }
    public DateTime Date { get; set; }
}
