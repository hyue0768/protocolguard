// Paper-guided reimplementation; not recovered author source.
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <set>
#include <map>
#include <vector>
using namespace llvm;
static std::string env(const char *k, const char *fallback) {
  auto v = std::getenv(k); return v ? v : fallback;
}
static void save(json::Value v, const std::string &name) {
  std::error_code ec; raw_fd_ostream out(name, ec);
  if(ec) report_fatal_error(Twine("Cannot write ")+name+": "+ec.message());
  out << formatv("{0:2}", v) << "\n";
}
static json::Object location(Instruction &I) {
  json::Object o;
  o["function"] = I.getFunction()->getName().str();
  if (auto dl=I.getDebugLoc()) {
    o["line"] = int64_t(dl.getLine());
    if(auto *scope=dyn_cast<DIScope>(dl.getScope())) {
      o["file"] = (scope->getDirectory()+"/"+scope->getFilename()).str();
    }
  }
  std::string s; raw_string_ostream os(s); I.print(os); o["ir"]=os.str(); return o;
}
// Local points-to discovery with a type-compatible address-taken fallback.
// Aggregate/global storage is intentionally field-insensitive. External and
// reflective targets remain unknown; this is not an SVF replacement.
static std::set<Function*> targets(CallBase *C, Module &M) {
  if(auto *F=dyn_cast<Function>(C->getCalledOperand()->stripPointerCasts()))return {F};
  std::set<Function*> result;std::set<Value*> visited;
  std::vector<Value*> pending{C->getCalledOperand()};bool unknown=false;
  while(!pending.empty()) {
    Value *V=pending.back()->stripPointerCasts();pending.pop_back();
    if(!visited.insert(V).second)continue;
    if(auto *F=dyn_cast<Function>(V)){result.insert(F);continue;}
    if(auto *P=dyn_cast<PHINode>(V)){for(auto &A:P->incoming_values())pending.push_back(A.get());continue;}
    if(auto *S=dyn_cast<SelectInst>(V)){pending.push_back(S->getTrueValue());pending.push_back(S->getFalseValue());continue;}
    if(auto *G=dyn_cast<GlobalVariable>(V)){if(G->hasInitializer())pending.push_back(G->getInitializer());else unknown=true;continue;}
    if(auto *L=dyn_cast<LoadInst>(V)) {
      auto *base=getUnderlyingObject(L->getPointerOperand());bool found=false;
      if(auto *G=dyn_cast<GlobalVariable>(base))if(G->hasInitializer()){pending.push_back(G->getInitializer());found=true;}
      for(auto &F:M)for(auto &B:F)for(auto &I:B)if(auto *S=dyn_cast<StoreInst>(&I))
        if(getUnderlyingObject(S->getPointerOperand())==base){pending.push_back(S->getValueOperand());found=true;}
      if(!found)unknown=true;
      continue;
    }
    if(auto *A=dyn_cast<Argument>(V)) {
      bool found=false;
      for(auto &F:M)for(auto &B:F)for(auto &I:B)if(auto *site=dyn_cast<CallBase>(&I))
        if(site->getCalledOperand()->stripPointerCasts()==A->getParent()&&A->getArgNo()<site->arg_size()){
          pending.push_back(site->getArgOperand(A->getArgNo()));found=true;
        }
      if(!found)unknown=true;
      continue;
    }
    if(auto *K=dyn_cast<Constant>(V)) {
      if(K->getNumOperands()){for(auto &O:K->operands())pending.push_back(O.get());}
      else if(!isa<ConstantPointerNull>(K))unknown=true;
      continue;
    }
    unknown=true;
  }
  if(result.empty()||unknown)for(auto &F:M)
    if(F.hasAddressTaken()&&F.getFunctionType()==C->getFunctionType())result.insert(&F);
  return result;
}
struct PGPass : PassInfoMixin<PGPass> {
  std::string kind;
  PGPass(std::string k):kind(k){}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
    json::Array functions, calls, assertions, selected, messageNodes;
    std::set<Function*> messageRoots;
    std::map<Function*, std::set<Function*>> edges, reverse;
    std::map<Function*,std::set<CallBase*>> callsites;
    std::map<CallBase*,std::set<Function*>> resolvedTargets;
    auto &FAM=AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    std::set<Value*> seen;
    std::vector<Value*> work;
    std::string handler, variable; int64_t seedLine=-1;
    if(kind=="match-pass") {
      auto input=MemoryBuffer::getFile(env("PG_CRITERIA", "criteria.json"));
      if(!input) report_fatal_error("Set PG_CRITERIA to an explicit JSON slicing decision file");
      auto parsed=json::parse((*input)->getBuffer());
      if(!parsed || !parsed->getAsObject()) report_fatal_error("Invalid PG_CRITERIA JSON");
      auto &o=*parsed->getAsObject();
      if(auto v=o.getString("handler")) handler=v->str();
      if(auto v=o.getString("variable")) variable=v->str();
      if(auto v=o.getInteger("line")) seedLine=*v;
      if(handler.empty()) report_fatal_error("criteria.handler required");
    }
    bool foundHandler=false;
    for(auto &F:M) {
      if(F.isDeclaration()) continue;
      json::Array args;
      for(auto &A:F.args()) args.push_back(A.getName().str());
      functions.push_back(json::Object{{"name",F.getName().str()},{"arguments",std::move(args)}});
      if(F.getName()==handler) {
        foundHandler=true;
        for(auto &A:F.args()) if(!variable.empty() && A.getName()==variable) work.push_back(&A);
      }
      for(auto &BB:F) for(auto &I:BB) {
        if(auto *C=dyn_cast<CallBase>(&I)) {
          auto *callee=C->getCalledFunction();
          resolvedTargets[C]=targets(C,M);
          for(auto *candidate:resolvedTargets[C]) {
            callsites[candidate].insert(C);
            edges[&F].insert(candidate);reverse[candidate].insert(&F);
            calls.push_back(json::Object{{"caller",F.getName().str()},
              {"callee",candidate->getName().str()},
              {"resolution",callee?"direct":"local-points-to-or-type-compatible-candidate"}});
          }
          if(callee) {
            edges[&F].insert(callee); reverse[callee].insert(&F);
            if(callee->getName()=="recv" || callee->getName()=="recvfrom" || callee->getName()=="recvmsg" || callee->getName()=="read") messageRoots.insert(&F);
          }
          if(!callee)calls.push_back(json::Object{{"caller",F.getName().str()},
            {"callee","<indirect-unresolved>"},{"resolution","external/alias completeness unproven"}});
          if(callee && (callee->getName().contains("assert") || callee->getName()=="abort")) assertions.push_back(location(I));
        }
        if(F.getName()==handler && ((!variable.empty() && I.getName()==variable) ||
            (seedLine>=0 && I.getDebugLoc() && I.getDebugLoc().getLine()==seedLine))) work.push_back(&I);
      }
    }
    // Conservative graph context around receive APIs. Buffer-origin/alias precision
    // requires external SVF decisions; this graph deliberately includes extra callers.
    std::set<Function*> ancestors=messageRoots;
    std::vector<Function*> pending(messageRoots.begin(),messageRoots.end());
    while(!pending.empty()) {
      auto *F=pending.back();pending.pop_back();
      for(auto *P:reverse[F])if(ancestors.insert(P).second)pending.push_back(P);
    }
    std::set<Function*> message=ancestors;
    pending.assign(ancestors.begin(),ancestors.end());
    while(!pending.empty()) {
      auto *F=pending.back();pending.pop_back();
      for(auto *C:edges[F])if(message.insert(C).second)pending.push_back(C);
    }
    for(auto *F:message)messageNodes.push_back(F->getName().str());
    bool fallback=false;
    if(kind=="match-pass") {
      if(!foundHandler) report_fatal_error("criteria.handler not found in module");
      // No field criterion: retain entire reachable handler subgraph (Algorithm 1, line 9).
      if(work.empty()) {
        if(!variable.empty() || seedLine>=0) report_fatal_error("Explicit criterion did not match debug line/SSA name");
        fallback=true; std::vector<Function*> todo{M.getFunction(handler)}; std::set<Function*> visited;
        while(!todo.empty()) {
          auto *F=todo.back();todo.pop_back(); if(!visited.insert(F).second)continue;
          for(auto &B:*F) for(auto &I:B) {
            work.push_back(&I);
            if(auto *C=dyn_cast<CallBase>(&I))for(auto *G:resolvedTargets[C])if(!G->isDeclaration())todo.push_back(G);
          }
        }
      }
      // Def-use fixed point, argument/formal propagation, return/caller propagation,
      // LLVM intra-function may-alias, cross-function same-object memory closure,
      // local indirect-call candidates, and conservative pointer side effects.
      while(!work.empty()) {
        Value *V=work.back(); work.pop_back(); if(!seen.insert(V).second)continue;
        for(auto *U:V->users()) {
          if(auto *I=dyn_cast<Instruction>(U)) work.push_back(I);
          if(auto *S=dyn_cast<StoreInst>(U)) if(S->getValueOperand()==V)work.push_back(S->getPointerOperand());
          if(auto *C=dyn_cast<CallBase>(U)) {
            for(auto *F:resolvedTargets[C])for(unsigned j=0;j<C->arg_size() && j<F->arg_size();++j)
              if(C->getArgOperand(j)==V)work.push_back(F->getArg(j));
            for(auto &A:C->args()) if(A->getType()->isPointerTy())work.push_back(A.get());
          }
          if(auto *R=dyn_cast<ReturnInst>(U))for(auto *C:callsites[R->getFunction()])work.push_back(C);
        }
        if(V->getType()->isPointerTy()) {
          auto *base=getUnderlyingObject(V);
          Function *owner=nullptr;
          if(auto *I=dyn_cast<Instruction>(V))owner=I->getFunction();
          if(auto *A=dyn_cast<Argument>(V))owner=A->getParent();
          for(auto &F:M)for(auto &B:F)for(auto &I:B) {
            Value *ptr=nullptr;
            if(auto *L=dyn_cast<LoadInst>(&I))ptr=L->getPointerOperand();
            if(auto *S=dyn_cast<StoreInst>(&I))ptr=S->getPointerOperand();
            if(!ptr)continue;
            bool mayAlias=getUnderlyingObject(ptr)==base;
            if(owner==&F) {
              auto &AA=FAM.getResult<AAManager>(F);
              mayAlias=mayAlias||(AA.alias(V,ptr)!=AliasResult::NoAlias);
            }
            if(mayAlias)work.push_back(&I);
          }
        }
      }
      for(auto &F:M)for(auto &B:F)for(auto &I:B)if(seen.count(&I))selected.push_back(location(I));
    }
    save(json::Object{{"backend","paper-guided-llvm"},{"pass",kind},{"functions",std::move(functions)},
      {"calls",std::move(calls)},{"message_context_functions",std::move(messageNodes)},{"assertions",std::move(assertions)},{"instructions",std::move(selected)},
      {"fallback_full_subgraph",fallback},
      {"alias_analysis","LLVM AA may-alias within function; same underlying object across functions"},
      {"indirect_analysis","local pointer sources plus type-compatible address-taken candidates; external completeness unproven"},
      {"unresolved_indirect_calls","retained even when candidates found; not a closed-world proof"}},
      env("PG_OUTPUT",(kind+".json").c_str()));
    return PreservedAnalyses::all();
  }
};
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
 return {LLVM_PLUGIN_API_VERSION,"ProtocolGuard",LLVM_VERSION_STRING,[](PassBuilder &PB){
  PB.registerPipelineParsingCallback([](StringRef N,ModulePassManager &PM,ArrayRef<PassBuilder::PipelineElement>){
   if(N=="protocolguard-analyze" || N=="match-pass" || N=="assert-call-analysis") {PM.addPass(PGPass(N.str()));return true;}return false;
  });
 }};
}
