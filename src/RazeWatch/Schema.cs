using System.Text.Json;
namespace RazeWatch;
public static class Schema
{
    public static void ValidateRecord(string file,JsonElement r)
    {
        void Require(bool value,string field){if(!value)throw new InvalidDataException("Schema mismatch: "+file+" / "+field);}
        bool String(string k)=>r.TryGetProperty(k,out var v)&&v.ValueKind==JsonValueKind.String;
        bool Int(string k)=>r.TryGetProperty(k,out var v)&&v.TryGetInt32(out _);
        bool Time(string k)=>r.TryGetProperty(k,out var v)&&v.ValueKind==JsonValueKind.String&&v.TryGetDateTimeOffset(out _);
        Require(r.ValueKind==JsonValueKind.Object,"object");
        if(file=="processes.jsonl"){
            Require(String("Kind")&&Time("Utc")&&Int("Pid")&&String("Source"),"process fields");
            Require(new[]{"start","stop","metadata","snapshot"}.Contains(r.GetProperty("Kind").GetString()),"process kind");
        }
        if(file=="flows.jsonl"){
            Require(Time("Utc")&&Time("EndUtc")&&Int("Pid")&&Int("Family")&&String("Protocol")&&String("LocalAddress")&&Int("LocalPort"),"flow fields");
            Require(r.GetProperty("Family").GetInt32() is 4 or 6,"family");Require(r.GetProperty("LocalPort").GetInt32() is >=0 and <=65535,"port");
            Require(r.GetProperty("Utc").GetDateTimeOffset()<=r.GetProperty("EndUtc").GetDateTimeOffset(),"time interval");
            Require(r.GetProperty("Protocol").GetString() is "TCP" or "UDP","protocol");
            if(r.GetProperty("Protocol").GetString()=="UDP")Require(r.GetProperty("RemoteAddress").ValueKind==JsonValueKind.Null&&r.GetProperty("RemotePort").ValueKind==JsonValueKind.Null,"UDP remote unknown");
        }
        if(file.StartsWith("events-")&&file.EndsWith(".jsonl"))Require(String("Channel")&&String("Provider")&&Int("Id")&&String("Xml"),"event provenance");
        if(file=="collection-log.jsonl")Require(String("Module")&&String("Status")&&Time("StartUtc")&&Time("EndUtc"),"health fields");
    }
}
