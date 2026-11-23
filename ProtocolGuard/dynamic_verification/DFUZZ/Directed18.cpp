// LLVM 18 adaptation: conservative interprocedural CFG distance and coverage.
// This is not the recovered SelectFuzz/AFLNet instrumentation.
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <map>
#include <set>
#include <queue>
using namespace llvm;
namespace {
struct DirectedPass : PassInfoMixin<DirectedPass> {
 PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
  auto criteriaPath=std::getenv("PG_DIRECTED_CRITERIA");
  auto outputPath=std::getenv("PG_DIRECTED_GRAPH");
  if(!criteriaPath||!outputPath)report_fatal_error("Set PG_DIRECTED_CRITERIA and PG_DIRECTED_GRAPH");
  auto input=MemoryBuffer::getFile(criteriaPath);
  if(!input)report_fatal_error("Cannot read directed criteria");
  auto parsed=json::parse((*input)->getBuffer());
  if(!parsed||!parsed->getAsObject())report_fatal_error("Invalid directed criteria");
  auto &criteria=*parsed->getAsObject();
  auto function=criteria.getString("function");auto line=criteria.getInteger("line");
  if(!function)report_fatal_error("criteria.function required");
  std::map<BasicBlock*,unsigned> ids;
  std::vector<BasicBlock*> blocks;
  for(auto &F:M)if(!F.isDeclaration()&&!F.getName().starts_with("__pg_"))for(auto &B:F){ids[&B]=blocks.size();blocks.push_back(&B);}
  std::vector<std::set<unsigned>> edges(blocks.size()),reverse(blocks.size());
  std::set<unsigned> targets;
  bool indirect=false, external=false;
  for(auto *B:blocks){
   auto id=ids[B];
   for(auto *next:successors(B))edges[id].insert(ids[next]);
   for(auto &I:*B){
    if(B->getParent()->getName()==*function&&(!line||(I.getDebugLoc()&&I.getDebugLoc().getLine()==*line)))targets.insert(id);
    if(auto *C=dyn_cast<CallBase>(&I)){
     auto *callee=C->getCalledFunction();
     std::set<Function*> candidates;
     if(callee)candidates.insert(callee);
     else {
      indirect=true;
      for(auto &F:M)if(F.hasAddressTaken()&&F.getFunctionType()==C->getFunctionType())candidates.insert(&F);
     }
     for(auto *candidate:candidates){
     if(candidate->isDeclaration()){if(!candidate->isIntrinsic())external=true;continue;}
     if(!ids.count(&candidate->getEntryBlock()))continue;
     edges[id].insert(ids[&candidate->getEntryBlock()]);
     // Context-insensitive return approximation: may return to any caller's successors.
     for(auto &exit:*candidate)if(isa<ReturnInst>(exit.getTerminator())){
      if(!ids.count(&exit))continue;
      if(succ_empty(B))edges[ids[&exit]].insert(id);
      for(auto *next:successors(B))edges[ids[&exit]].insert(ids[next]);
     }
     }
    }
   }
  }
  if(targets.empty())report_fatal_error("No target block matched; refuse meaningless distances");
  for(unsigned i=0;i<edges.size();++i)for(auto next:edges[i])reverse[next].insert(i);
  std::vector<int> distance(blocks.size(),-1);std::queue<unsigned> work;
  for(auto target:targets){distance[target]=0;work.push(target);}
  while(!work.empty()){auto n=work.front();work.pop();for(auto p:reverse[n])if(distance[p]<0){distance[p]=distance[n]+1;work.push(p);}}
  auto &C=M.getContext();auto *i32=Type::getInt32Ty(C);
  auto visit=M.getOrInsertFunction("__pg_visit",FunctionType::get(Type::getVoidTy(C),{i32,i32},false));
  json::Array output;
  for(auto *B:blocks){
   auto id=ids[B];json::Array next;for(auto n:edges[id])next.push_back(int64_t(n));
   json::Object row{{"id",int64_t(id)},{"function",B->getParent()->getName().str()},
                    {"distance",int64_t(distance[id])},{"target",targets.count(id)>0},{"successors",std::move(next)}};
   for(auto &I:*B)if(auto loc=I.getDebugLoc()){row["line"]=int64_t(loc.getLine());break;}
   output.push_back(std::move(row));
   auto insertion=B->getFirstInsertionPt();
   if(insertion==B->end())report_fatal_error("No safe block instrumentation point");
   IRBuilder<> builder(&*insertion);
   builder.CreateCall(visit,{builder.getInt32(id),builder.getInt32(distance[id])});
  }
  std::error_code ec;raw_fd_ostream out(outputPath,ec,sys::fs::OF_None);
  if(ec)report_fatal_error("Cannot save directed graph");
  out<<formatv("{0:2}",json::Value(json::Object{{"blocks",std::move(output)},
       {"method","unit-edge reverse BFS; direct calls and type-compatible address-taken indirect candidates; context-insensitive returns"},
       {"unresolved_indirect_calls",indirect},{"external_calls",external},
       {"reachability_proven",false}}))<<"\n";
  return PreservedAnalyses::none();
 }
};
}
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo(){
 return {LLVM_PLUGIN_API_VERSION,"ProtocolGuardDirected18","1",[](PassBuilder &PB){
  PB.registerPipelineParsingCallback([](StringRef name,ModulePassManager &PM,ArrayRef<PassBuilder::PipelineElement>){
   if(name!="pg-directed")return false;PM.addPass(DirectedPass());return true;
  });
 }};
}
